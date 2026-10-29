//! Whether an owner-plane verdict still answers the policy in force, and
//! what the plane answers when it does not. Every owner door that hands a
//! verdict out asks here, in the transaction that writes its row.

use crate::Vault;
use crate::error::Result;
use crate::gate;

use super::binding::content_binding;
use super::planes::PolicyPlane;
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{PolicyClassifyVerdict, PolicySkipReason};

impl Vault {
    pub fn policy_model_verdict_is_stale(
        &self,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
    ) -> Result<bool> {
        self.policy_model_verdict_is_stale_with_config(
            verdict,
            request,
            &PolicyModelConfig::default(),
        )
    }

    /// Whether the manifest has moved out from under a verdict, so a caller
    /// about to act on it should derive a fresh one first.
    ///
    /// Two things can go stale, and they are asked about separately.
    ///
    /// The CONTENT half of the binding — subject, content, world, safeguard
    /// selector — is about the question. A verdict for other content, another
    /// world or another classifier is not this verdict, whatever the plane is
    /// doing.
    ///
    /// The FRONTIER half is about the manifest the plane decided against, and
    /// it is only asked of a plane that is ON. A disabled plane decides
    /// nothing, so an edit elsewhere in the manifest cannot invalidate its
    /// clean allow — and reporting it stale only sends the caller to re-derive
    /// its way back to the identical clean allow. Mirrors the same
    /// short-circuit the live-context resolver already applies.
    ///
    /// That short-circuit is about the CLEAN ALLOW, not about the plane. A
    /// plane that is off returns the inert clean allow and can return nothing
    /// else, so any other verdict in a caller's hand was minted while the
    /// plane was ON and the owner has since opted out. Reporting that one
    /// fresh would let a `Block` the owner switched off keep blocking, which
    /// is the owner-sovereignty violation this whole predicate exists to
    /// prevent — so the ON to OFF transition reads STALE.
    ///
    /// The DIAL is asked beside the frontier, and only of a live plane for the
    /// same reason. It is the owner dial and never the hosted one: a hosted
    /// flip has nothing to say about a verdict the owner plane decided. Both
    /// directions matter. A clean allow minted under `PatternGated` must not
    /// survive a flip to `ClassifyAll` — that releases content the config now
    /// says a model has to look at. And a `Block` the model decided under
    /// `ClassifyAll` must not survive a flip to `PatternGated` where nothing
    /// escalates, which is the same switched-off rule still enforcing, arrived
    /// at by a different route. A verdict recording NO dial at all predates
    /// the field and reads stale, because a compat gap that guesses is a
    /// compat gap that releases content.
    pub fn policy_model_verdict_is_stale_with_config(
        &self,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        self.policy_model_verdict_is_stale_in_txn(&rtxn, verdict, request, config)
    }

    /// The owner-plane verdict a door may hand out from `txn`: `verdict`
    /// while it answers the policy in force there, and otherwise what the
    /// plane answers with no verdict for that policy
    /// ([`Vault::owner_plane_fail_open_in_txn`]). The flag says the frontier
    /// moved.
    ///
    /// The owner plane is SOVEREIGN and fails OPEN, so a manifest that moved
    /// after the pass is not an error. What it never does is hand out a
    /// decision for a policy no longer in force: not an old Allow, and not an
    /// old warn or block either, which stamped with the new frontier would
    /// pass the enforcement door's freshness check as if the new policy had
    /// reached it.
    pub(super) fn owner_verdict_in_force_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<(PolicyClassifyVerdict, bool)> {
        if !self.policy_model_verdict_is_stale_in_txn(txn, verdict, request, config)? {
            return Ok((verdict.clone(), false));
        }
        Ok((
            self.owner_plane_fail_open_in_txn(txn, request, config)?,
            true,
        ))
    }

    /// What the owner plane answers from `txn` when it holds no verdict for
    /// the policy in force there.
    ///
    /// A plane the owner has switched OFF answers as an off plane always
    /// does, with the inert clean allow: the opt-out releases what the old
    /// verdict held, and that allow is the one verdict the enforcement door
    /// takes from an off plane. A live plane fails open with
    /// [`PolicySkipReason::PolicyMoving`] bound to the frontier in force.
    pub(super) fn owner_plane_fail_open_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<PolicyClassifyVerdict> {
        let policy = gate::resolve_policy_manifest(&self.store, txn)?;
        let binding = content_binding(request, &policy, config)?;
        if !policy.owner_policy_enabled()
            && !policy.diagnostics().loaded_manifest_forces_fail_closed()
            && !policy.owner_policy_rows_dropped()
        {
            return Ok(PolicyClassifyVerdict::clean_allow(
                binding,
                config,
                PolicyPlane::OwnerPolicy,
            ));
        }
        Ok(PolicyClassifyVerdict::skipped(
            PolicySkipReason::PolicyMoving,
            binding,
            config,
            PolicyPlane::OwnerPolicy,
        ))
    }

    /// Whether the owner plane is on in the policy in force (FIX 7805): a
    /// clean allow it gives examined the content and is receipted; an off
    /// plane's inert allow examined nothing and leaves no row.
    pub(super) fn owner_plane_examines(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(gate::resolve_policy_manifest(&self.store, &rtxn)?.owner_policy_enabled())
    }

    pub(super) fn policy_model_verdict_is_stale_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        verdict: &PolicyClassifyVerdict,
        request: &PolicyClassifyRequest,
        config: &PolicyModelConfig,
    ) -> Result<bool> {
        let policy = gate::resolve_policy_manifest(&self.store, rtxn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed()
            || policy.owner_policy_rows_dropped()
        {
            return Ok(true);
        }
        let fresh = content_binding(request, &policy, config)?;
        if verdict.binding.content_hash != fresh.content_hash
            || verdict.safeguard_binding != config.safeguard_binding.selector()
            || verdict.decision_binding != config.decision_binding(PolicyPlane::OwnerPolicy)
        {
            return Ok(true);
        }
        if policy.owner_policy_enabled() {
            return Ok(
                verdict.binding.read_frontier_hash != fresh.read_frontier_hash
                    || verdict.classifier_mode != Some(config.owner_classifier_mode),
            );
        }
        Ok(!verdict.is_inert_clean_allow())
    }
}

/// Declares [`SettlingDoor`] and its `ALL` list from one list of doors, so
/// the list a check walks cannot miss a door the enum names.
#[cfg(test)]
macro_rules! settling_doors {
    ($($(#[doc = $doc:literal])* $door:ident,)*) => {
        /// Every door that hands out a settled result, named by the point
        /// just before the transactions that settle it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) enum SettlingDoor {
            $($(#[doc = $doc])* $door,)*
        }

        impl SettlingDoor {
            pub(super) const ALL: &'static [Self] = &[$(Self::$door,)*];
        }
    };
}

#[cfg(test)]
settling_doors! {
    /// `record_bare_classify_receipt`: the bare classify doors.
    BareClassify,
    /// `enforcement_from_verdict` writing its own row: the classify-and-enforce
    /// doors.
    RecordAndEnforce,
    /// `stale_owner_plane_fail_open`: an enforce door whose pass would not
    /// hold still.
    StaleFailOpen,
    /// `enforcement_from_verdict` on a verdict another door recorded:
    /// `enforce_policy_model_verdict`.
    EnforceRecorded,
    /// `classify_both_planes`, before its final transaction.
    DualPlane,
    /// `record_relay_receipt`: `relay_boundary_pass`, and the relay half of
    /// the dual-plane door.
    RelayBoundary,
    /// `stateless_owner_classification`: the anonymous chat turn.
    AnonymousChat,
}

/// A hook a test runs at a settling point.
#[cfg(test)]
pub(super) type SettlingHook = Box<dyn FnMut(SettlingDoor)>;

#[cfg(test)]
thread_local! {
    /// Runs as a door reaches the transactions that settle what it hands
    /// out: the window between a pinned pass and the door's last
    /// transaction.
    pub(super) static BEFORE_SETTLING: std::cell::RefCell<Option<SettlingHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn before_settling(door: SettlingDoor) {
    // Out of the slot while it runs, so a hook that drives a door does not
    // find itself there.
    let Some(mut hook) = BEFORE_SETTLING.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    hook(door);
    BEFORE_SETTLING.with(|slot| {
        slot.borrow_mut().get_or_insert(hook);
    });
}
