//! Purposes of identity topology (`crates/oneiron/src/identity_topology`,
//! `dreamer_runner::maintenance::identity`).

purposes! {
    /// The fork a FACET event births for one reassigned claim, so the undo door recovers
    /// every fork from the stored event (`identity_topology::op_apply`). Parts: event,
    /// origin.
    FACET_FORK = "oneiron/identity-topology/facet-fork/v1";

    /// A topology audit recipe (`identity_topology::post_hoc_review::run`). Parts: name.
    TOPOLOGY_AUDIT_RECIPE = "oneiron/coach/topology-audit-recipe/v1";

    /// An identity ask's answer (`dreamer_runner::maintenance::identity::settlement`).
    /// Parts: the answer key.
    ASK_ANSWER = "oneiron/identity-ask/answer/v1";
}

legacy_purposes! {}
