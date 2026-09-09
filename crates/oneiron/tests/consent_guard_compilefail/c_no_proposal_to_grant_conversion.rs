//! (c) There is no `From<ConsentProposal> for ConsentGrant` either: the guard
//! cannot skip the owner entirely and mint the authorization itself. (Kept in
//! its own case file so neither missing-impl diagnostic masks the other.)

fn launder(proposal: oneiron::consent::ConsentProposal) -> oneiron::consent::ConsentGrant {
    proposal.into()
}

fn main() {
    let _ = launder;
}
