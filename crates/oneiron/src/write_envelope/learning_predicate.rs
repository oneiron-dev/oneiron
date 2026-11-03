//! The measured-state claim family and its namespace classifier.

/// How often a thing worked.
pub const PREDICATE_LEARNING_RELIABILITY: &str = "learning.reliability";
/// How much people had to fix.
pub const PREDICATE_LEARNING_EDIT_COST: &str = "learning.edit_cost";
/// How often a judge disagrees with itself.
pub const PREDICATE_LEARNING_RETEST_NOISE: &str = "learning.retest_noise";
/// The fitted value of a named knob.
pub const PREDICATE_LEARNING_SETTING: &str = "learning.setting";

/// The whole family, an exact table: an unknown future `learning.*`
/// predicate is not silently read as one of these.
pub const LEARNING_PREDICATES: &[&str] = &[
    PREDICATE_LEARNING_RELIABILITY,
    PREDICATE_LEARNING_EDIT_COST,
    PREDICATE_LEARNING_RETEST_NOISE,
    PREDICATE_LEARNING_SETTING,
];

/// The family's namespace, engine-reserved.
pub use crate::write_envelope::claim_predicate::LEARNING_NAMESPACE;

/// Whether `predicate` is in the `learning` namespace. Companion memory reads
/// exclude every such claim: learning views only.
#[must_use]
pub fn is_learning_predicate(predicate: &str) -> bool {
    predicate.split('.').next() == Some(LEARNING_NAMESPACE)
}
