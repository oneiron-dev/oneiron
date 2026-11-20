//! The catalogue key `edit_distance::graduation` declares (DESIGN 15-setting-primitive, stage 4):
//! the owner's graduation threshold rows (ED-05).

use crate::entity_id::EntityId;
use crate::setting::Kind;

use super::threshold_policy::GraduationThresholds;

/// No runtime row: the compiled catch-all governs every scope.
fn no_rows() -> GraduationThresholds {
    GraduationThresholds::default()
}

/// An erase of `id` takes out each row whose pattern names `id` as the scope's actor: that
/// scope's policy goes with its actor (RAMP-SCOPE-ACTOR-ERASE, Engine RULING NEXT-ROW-18 = A1).
fn erase_actor(value: &GraduationThresholds, id: EntityId) -> Option<GraduationThresholds> {
    value.without_actor(&id.to_hex())
}

crate::setting::setting_keys! {
    /// The owner's graduation threshold rows (ED-05): for each scope pattern
    /// (`op_kind/target_class/actor`, each a literal or `*`), the clean streak and the posterior
    /// guard a scope must clear before the engine offers to stop asking, and the snooze backoffs
    /// after a first and second decline. At most one row per pattern; the most specific row that
    /// governs a scope decides, and with no row the compiled catch-all does.
    pub(crate) GRADUATION_THRESHOLDS: GraduationThresholds = "edit_distance.graduation.thresholds" {
        kind: Kind::new(no_rows).erase_mentions(erase_actor),
    };
}
