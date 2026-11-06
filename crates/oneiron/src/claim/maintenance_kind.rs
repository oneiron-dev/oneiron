//! Queue and facet identifiers for maintenance work.

/// Host-run Coach queue kind. The payload `job_type` names the facet.
pub const COACH_HOST_QUEUE_KIND: &str = "coach.host";

/// Digest settings (FIX 5609): each owner's rhythm or lead step, drafted by
/// the Coach's model and filed through [`Vault::run_coach_weave_digest_settings`].
pub const COACH_WEAVE_DIGEST_SETTINGS_FACET: &str = "coach.weave_digest_settings";

/// Eval authoring (OF-578, ARCH-0053): each seat's test set kept from the
/// vault's own history by the eval-authoring skill, and applied through
/// [`Vault::run_coach_eval_authoring`].
pub const COACH_EVAL_AUTHORING_FACET: &str = "coach.eval_authoring";

/// Training offers (OF-577), drafted on the host from the offer skill's draft
/// and recorded through [`Vault::run_coach_training_offer`].
pub const COACH_TRAINING_OFFER_FACET: &str = "coach.training_offer";

/// Issues (ARCH-0066 #coach, OF-418): the blocked reports agents filed, each
/// asked which fix its agent needs and filed as a proposed heal. A report
/// wakes it at once; the nightly pass wakes it again while reports wait.
pub const COACH_ISSUES_FACET: &str = "coach.issues";
