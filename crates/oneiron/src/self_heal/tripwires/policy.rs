//! The tripwire policy a pass applied, as it was resolved (FIX 10096): the
//! four bounds every detector of the pass reads, and where each came from:
//! a trusted policy manifest row that states it, the default of a field
//! those rows omit, or the compiled fallback when no row states the bounds.
//! The receipt rides the pass's signed run. It records; it decides nothing,
//! and the numbers are the ones the detectors read.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::TripwireBounds;
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Error, Result, Vault};

/// The scope a resolved tripwire policy covers: the vault's manifest fold.
const POLICY_SCOPE: &str = "vault";

/// One manifest row's tripwire bounds as decoded, with whether the row
/// omitted its fourth field. The omission is carried for the receipt and
/// is never consulted to admit or refuse anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManifestTripwireBounds {
    pub(crate) bounds: TripwireBounds,
    pub(crate) omits_retrieval_regressions: bool,
}

impl ManifestTripwireBounds {
    /// [`TripwireBounds::decode`]'s verdict and numbers, unchanged, with the
    /// row's omission of `retrieval_regressions` beside them.
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let bounds = TripwireBounds::decode(value)?;
        Some(Self {
            bounds,
            omits_retrieval_regressions: value.as_map()?.len() == 3,
        })
    }

    /// Notes this trusted row, `manifest` with body `body`, beside the
    /// fold's `resolved` bounds when it agrees with them: every agreeing row
    /// is a source, sorted by id, and none is chosen over another. A field
    /// is stated when any agreeing row states it. A row that disagrees is the
    /// fold's to flag and no source of the value.
    pub(crate) fn attribute(
        self,
        origin: &mut Option<TripwireBoundsOrigin>,
        resolved: Option<TripwireBounds>,
        manifest: EntityId,
        body: &[u8],
    ) {
        if resolved != Some(self.bounds) {
            return;
        }
        let origin = origin.get_or_insert_with(TripwireBoundsOrigin::default);
        let source = TripwirePolicySource {
            manifest,
            revision: *blake3::hash(body).as_bytes(),
        };
        if let Err(at) = origin.sources.binary_search(&source) {
            origin.sources.insert(at, source);
        }
        origin.states_retrieval_regressions |= !self.omits_retrieval_regressions;
    }
}

/// The trusted manifest rows behind the fold's tripwire bounds, sorted by
/// id, and whether any of them states the fourth field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TripwireBoundsOrigin {
    pub(crate) sources: Vec<TripwirePolicySource>,
    pub(crate) states_retrieval_regressions: bool,
}

/// Where one effective tripwire bound came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripwireBoundOrigin {
    /// A trusted policy manifest row states it.
    Manifest,
    /// The trusted rows that state the bounds omit this field, so its
    /// default applies.
    OmittedFieldDefault,
    /// No trusted row states the bounds, so the compiled default applies.
    CompiledFallback,
}

/// One effective tripwire bound and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwireBound {
    /// The number the pass's detectors read.
    pub value: u64,
    /// Where it came from.
    pub origin: TripwireBoundOrigin,
}

/// One trusted policy manifest row a resolved tripwire policy read: its id
/// and the BLAKE3 of the body it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TripwirePolicySource {
    /// The manifest row's id.
    pub manifest: EntityId,
    /// The BLAKE3 of the row's body as the fold read it.
    pub revision: [u8; 32],
}

/// The tripwire policy one pass applied (FIX 10096): its four effective
/// bounds, each with its origin, the scope they cover, and every trusted
/// manifest row that supplied them, sorted by id. Signed with the pass's
/// detector run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripwirePolicyReceipt {
    /// The scope the policy covers.
    pub scope: String,
    /// The fixed-window length, in seconds.
    pub window_secs: TripwireBound,
    /// The consent-storm and consent-queue depth.
    pub consent_depth: TripwireBound,
    /// The actor-write drift threshold.
    pub actor_writes: TripwireBound,
    /// The degraded retrieval runs one window reads as a regression.
    pub retrieval_regressions: TripwireBound,
    /// Every trusted manifest row the bounds came from, by id; none for the
    /// compiled fallback.
    pub sources: Vec<TripwirePolicySource>,
}

impl TripwirePolicyReceipt {
    /// The receipt's bytes as a signed run's transcript carries them.
    pub(crate) fn transcript_bytes(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("tripwire policy encode"))
    }
}

/// The bounds a pass's detectors read, resolved once, with the receipt of
/// how they were resolved. Every detector, producer and signed run of the
/// pass reads this same value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTripwireBounds {
    /// The effective bounds.
    pub bounds: TripwireBounds,
    /// Where each came from.
    pub receipt: TripwirePolicyReceipt,
}

impl ResolvedTripwireBounds {
    fn resolve(stated: Option<TripwireBounds>, origin: Option<&TripwireBoundsOrigin>) -> Self {
        let bounds = stated.unwrap_or_default();
        let origin_of = |stated_here: bool| match (stated, stated_here) {
            (None, _) => TripwireBoundOrigin::CompiledFallback,
            (Some(_), true) => TripwireBoundOrigin::Manifest,
            (Some(_), false) => TripwireBoundOrigin::OmittedFieldDefault,
        };
        let bound = |value, stated_here| TripwireBound {
            value,
            origin: origin_of(stated_here),
        };
        let fourth = origin.is_some_and(|origin| origin.states_retrieval_regressions);
        Self {
            bounds,
            receipt: TripwirePolicyReceipt {
                scope: POLICY_SCOPE.to_owned(),
                window_secs: bound(bounds.window_secs, true),
                consent_depth: bound(bounds.consent_depth, true),
                actor_writes: bound(bounds.actor_writes, true),
                retrieval_regressions: bound(bounds.retrieval_regressions, fourth),
                sources: origin
                    .map(|origin| origin.sources.clone())
                    .unwrap_or_default(),
            },
        }
    }
}

impl Vault {
    /// The resolved tripwire policy with its receipt (FIX 10096); `None`
    /// when a manifest forces tripwires closed. Each of its three count
    /// thresholds past `limits.tripwire_threshold` asks whether everything
    /// is okay, and the tripwires run at it.
    pub fn resolved_tripwire_bounds(&self) -> Result<Option<ResolvedTripwireBounds>> {
        let txn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        if policy.diagnostics().loaded_manifest_forces_fail_closed() {
            return Ok(None);
        }
        let resolved = ResolvedTripwireBounds::resolve(
            policy.diagnostic_bounds,
            policy.diagnostic_bounds_origin.as_ref(),
        );
        for threshold in [
            resolved.bounds.consent_depth,
            resolved.bounds.actor_writes,
            resolved.bounds.retrieval_regressions,
        ] {
            let _ = self.measure_limit(EngineLimit::TripwireThreshold, threshold);
        }
        Ok(Some(resolved))
    }
}
