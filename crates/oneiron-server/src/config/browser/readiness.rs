//! The server's browser readiness (FIX 7670): one value, seeded at start
//! from the `[browser]` section, its runtime binding and the supervisor's
//! guest runtime fact, then moved by each browser guest start this process
//! makes: the `browser.session` check, a run's browser (its first guest, an
//! engine switch's target and a replay's fresh guest) and the web fetch's
//! headless render. The last start to complete stands. Nothing here starts
//! a guest, probes, expires or persists, and a desktop start never moves
//! it. A managed `Ping` and the owner's status read it.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron_container::SessionManifest;
use oneiron_vault_contract::{
    BrowserReadiness, BrowserTier, BrowserUnavailableReason, GuestRuntimeFact, now_ts,
};

use super::BrowserConfig;

/// The server's browser readiness; every clone shares the one value.
#[derive(Clone, Debug)]
pub(crate) struct BrowserReadinessCell(Arc<Mutex<BrowserReadiness>>);

impl Default for BrowserReadinessCell {
    /// `NotConfigured`, until the start seeds it.
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BrowserReadiness::NotConfigured)))
    }
}

impl BrowserReadinessCell {
    /// Sets the value this process starts from: `NotConfigured` with no
    /// section, `Bound` when its runtime is bound and `ConfiguredUnbound`
    /// when not, carrying `fact`, the supervisor's for this spawn.
    pub(crate) fn seed(&self, section: Option<&BrowserConfig>, fact: Option<GuestRuntimeFact>) {
        *self.lock() = match section {
            None => BrowserReadiness::NotConfigured,
            Some(section) if section.runtime.is_some() => BrowserReadiness::Bound {
                image: section.image.clone(),
                runtime_fact: fact,
            },
            Some(section) => BrowserReadiness::ConfiguredUnbound {
                image: section.image.clone(),
                runtime_fact: fact,
            },
        };
    }

    /// The value now.
    pub(crate) fn snapshot(&self) -> BrowserReadiness {
        self.lock().clone()
    }

    /// A start whose browser driver attached to its guest: `VerifiedStart`,
    /// with the image and the sandbox `manifest` names. A manifest that
    /// proves no sandbox names no tier, and moves nothing.
    pub(crate) fn started(&self, manifest: &SessionManifest) {
        let Some(tier) = tier(manifest) else {
            return;
        };
        let mut readiness = self.lock();
        let Some((_, runtime_fact)) = configured(&readiness) else {
            return;
        };
        *readiness = BrowserReadiness::VerifiedStart {
            image: manifest.image.clone(),
            tier,
            last_observed_at: now_ts(),
            runtime_fact,
        };
    }

    /// A start that stopped at `reason`'s phase: `Unavailable`, with the
    /// configured image.
    pub(crate) fn unavailable(&self, reason: BrowserUnavailableReason) {
        let mut readiness = self.lock();
        let Some((image, runtime_fact)) = configured(&readiness) else {
            return;
        };
        *readiness = BrowserReadiness::Unavailable {
            image,
            reason,
            last_observed_at: now_ts(),
            runtime_fact,
        };
    }

    fn lock(&self) -> MutexGuard<'_, BrowserReadiness> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The image and the runtime fact a configured readiness carries; none
/// with no section, where no guest starts.
fn configured(readiness: &BrowserReadiness) -> Option<(String, Option<GuestRuntimeFact>)> {
    match readiness {
        BrowserReadiness::NotConfigured => None,
        BrowserReadiness::ConfiguredUnbound {
            image,
            runtime_fact,
        }
        | BrowserReadiness::Bound {
            image,
            runtime_fact,
        }
        | BrowserReadiness::VerifiedStart {
            image,
            runtime_fact,
            ..
        }
        | BrowserReadiness::Unavailable {
            image,
            runtime_fact,
            ..
        } => Some((image.clone(), *runtime_fact)),
    }
}

/// The sandbox a manifest proves its guest ran in, by the backend that
/// wrote it: a Firecracker microVM's, or the fenced OCI container's. A
/// manifest with no fence proof, the unfenced container CLI's among them,
/// proves neither.
fn tier(manifest: &SessionManifest) -> Option<BrowserTier> {
    if manifest.fence_unproven || manifest.fence_proof.is_none() {
        return None;
    }
    match manifest.backend.as_str() {
        "firecracker-oci" => Some(BrowserTier::Firecracker),
        "landlock-container" => Some(BrowserTier::FencedOci),
        _ => None,
    }
}
