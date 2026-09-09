//! (b) There is no `From<ConsentProposal> for AuthenticatedOwner`: a proposal
//! cannot be converted into the owner stamp that `Vault::create_standing_grant`
//! demands. Inference is not authority, and no blanket or convenience impl
//! launders it into one.

fn launder(proposal: oneiron::consent::ConsentProposal) -> oneiron::consent::AuthenticatedOwner {
    proposal.into()
}

fn main() {
    let _ = launder;
}
