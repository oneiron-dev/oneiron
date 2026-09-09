//! (a) A guard holding a `ConsentProposal` must not be able to struct-literal
//! an `AuthenticatedOwner`: all three fields are private, so the only door is
//! `Vault::authenticate_owner`. Every field VALUE below is well-typed and
//! publicly constructible on purpose — the sole thing between a guard and a
//! forged owner stamp is the field privacy this case pins.

fn launder(proposal: oneiron::consent::ConsentProposal) -> oneiron::consent::AuthenticatedOwner {
    let _ = proposal.confidence;
    oneiron::consent::AuthenticatedOwner {
        actor: oneiron::EntityId::now(),
        principal_ref: String::new(),
        decision_id: oneiron::store::GateDecisionId::now(),
    }
}

fn main() {
    let _ = launder;
}
