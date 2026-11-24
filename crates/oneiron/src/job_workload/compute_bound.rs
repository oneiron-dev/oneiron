//! The `compute.pin` standing grant (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5; row R7 folded into R2's follow-up): the built consent action
//! bound, whose selectors name what a covered pin may use. The owner mints it
//! with `vault.consent.create_standing_grant` and its typed `compute` field,
//! lists it in `vault.consent.registry` and revokes it with
//! `vault.consent.revoke`. No store type and no verb are new.
//!
//! - The actor is the Grant an agent pins under: a Grant names one agent, and
//!   the start gate judges starters by their Grant. The target is the project
//!   the pin names; a pin that names none is never covered (a target-pinned
//!   bound never covers an unpinned candidate).
//! - The candidate never leaves out an axis, because containment is "every
//!   selector of the candidate is in the bound": it names the pin's template,
//!   network mode and scope kind. A pin names no machine. The start gate's
//!   check adds `machine:<id>` and reads the grants again before every
//!   reservation, so a revoked or narrowed grant stops the next start.
//! - A template fixes its entry, its repository (pass 33: one mirror per
//!   template, bound by the template digest the pin names) and its ceilings,
//!   so the grant names templates and no commit or size: a new revision is a
//!   new pin inside the bound.
use oneiron_verb_wire::consent::lifecycle::{ComputeEnvelopeRequest, ComputeNetwork, ComputeScope};

use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::error::{Error, GateError, Result};
use crate::{EntityId, Vault};

use super::{NetworkMode, ScopeKind, WorkloadPin};

/// The action class of a compute standing grant.
pub const COMPUTE_PIN_CLASS: &str = "compute.pin";

fn template_selector(name: &str) -> String {
    format!("template:{name}")
}

const fn network_selector(network: ComputeNetwork) -> &'static str {
    match network {
        ComputeNetwork::None => "network:none",
        ComputeNetwork::Host => "network:host",
    }
}

const fn scope_selector(scope: ComputeScope) -> &'static str {
    match scope {
        ComputeScope::Host => "scope:host",
        ComputeScope::Container => "scope:container",
    }
}

fn machine_selector(machine: EntityId) -> String {
    format!("machine:{}", machine.to_hex())
}

fn project_selector(project: &str) -> String {
    format!("project:{project}")
}

const fn pin_network(network: NetworkMode) -> ComputeNetwork {
    match network {
        NetworkMode::None => ComputeNetwork::None,
        NetworkMode::Host => ComputeNetwork::Host,
    }
}

const fn pin_scope(scope: &ScopeKind) -> ComputeScope {
    match scope {
        ScopeKind::Host => ComputeScope::Host,
        ScopeKind::Container { .. } => ComputeScope::Container,
    }
}

fn refused(what: &'static str) -> Error {
    Error::Gate(GateError::InvalidConsentBound(what))
}

/// The selectors the mint's `compute` field adds to an action bound of class
/// `class`: one per template, network mode, scope kind and machine. A
/// `compute` field goes only with class [`COMPUTE_PIN_CLASS`], and that class
/// only with one; each list names at least one value.
///
/// # Errors
///
/// `InvalidConsentBound` for a `compute` field and class that do not go
/// together, an empty list, an empty or oversized template name, or a
/// machine that is not an id in hex.
pub(crate) fn compute_selectors(
    class: &str,
    compute: Option<ComputeEnvelopeRequest>,
) -> Result<Vec<String>> {
    let compute = match (class.trim() == COMPUTE_PIN_CLASS, compute) {
        (false, None) => return Ok(Vec::new()),
        (true, Some(compute)) => compute,
        (true, None) => return Err(refused("a compute.pin bound names its compute field")),
        (false, Some(_)) => return Err(refused("a compute field goes only with compute.pin")),
    };
    if compute.templates.is_empty()
        || compute.network.is_empty()
        || compute.scopes.is_empty()
        || compute.machines.is_empty()
    {
        return Err(refused(
            "a compute field names at least one template, network mode, scope and machine",
        ));
    }
    let mut selectors = Vec::new();
    for name in compute.templates {
        let name = crate::store::consent_bound::normalized_ref("compute template", name)?;
        selectors.push(template_selector(&name));
    }
    selectors.extend(
        compute
            .network
            .into_iter()
            .map(|network| network_selector(network).to_owned()),
    );
    selectors.extend(
        compute
            .scopes
            .into_iter()
            .map(|scope| scope_selector(scope).to_owned()),
    );
    for machine in compute.machines {
        let machine =
            EntityId::from_hex(machine.trim()).map_err(|_| refused("a compute machine id"))?;
        selectors.push(machine_selector(machine));
    }
    Ok(selectors)
}

/// The bound a pin made under `grant` for `project` asks to be covered by:
/// its template, network mode and scope kind, and `machine:<id>` when
/// `machine` names the machine a start runs on.
///
/// # Errors
///
/// A template name the consent bound refuses (empty or oversized).
pub(crate) fn pin_candidate(
    grant: EntityId,
    project: Option<EntityId>,
    pin: &WorkloadPin,
    machine: Option<EntityId>,
) -> Result<GrantBound> {
    let mut selectors = vec![
        template_selector(&pin.template),
        network_selector(pin_network(pin.network)).to_owned(),
        scope_selector(pin_scope(&pin.scope)).to_owned(),
    ];
    selectors.extend(machine.map(machine_selector));
    let project = project.map(|project| project.to_hex());
    selectors.extend(project.as_deref().map(project_selector));
    let mut envelope = ActionEnvelope::new(selectors)?;
    if let Some(project) = project {
        envelope = envelope.with_target(project)?;
    }
    GrantBound::action(
        ActorBound::new(grant.to_hex())?,
        ActionClass::new(COMPUTE_PIN_CLASS)?,
        envelope,
    )
}

impl Vault {
    /// The digest (lower hex) of a live standing grant that covers
    /// `candidate`, read in `txn`, or `None`. Revoked grants are not read.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn covering_compute_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        candidate: &GrantBound,
    ) -> Result<Option<String>> {
        Ok(self
            .active_standing_consent_grants_in_txn(txn)?
            .iter()
            .map(|grant| grant.bound())
            .find(|bound| bound.contains(candidate))
            .map(|bound| bound.digest().to_hex()))
    }
}
