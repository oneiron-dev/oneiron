//! `self.team.submit` (OF-540): what a team's leader submits for the owner's
//! review, and what the host answers. The leader, the review and its binding
//! are the host's; the guest names only the team and the output. An output
//! is a blob version, a code revision, or (FIX 2783) one exact revision of a
//! CLAIM or of a record's common document.

pub(crate) use crate::gate::team_review::TEAM_DELIVERABLE_REVIEW_PREDICATE;

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::team_submit::TeamSubmitInput;

#[doc(hidden)]
pub use oneiron_records::code_run::team_submit::TeamSubmitAnswer;
