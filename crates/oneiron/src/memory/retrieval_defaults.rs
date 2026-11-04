/// Default recency half-life in days (ARCH-0004 `RECENCY_DECAY`,
/// 28-day default). The recency signal's source timestamp is the
/// entity's `learned_at` (v1). This named constant is the engine
/// default for unlisted dynamic type bytes; the temporal pipeline's
/// recency decay constant (`RECENCY_DECAY_TAU_SECS = 28.0 * 86_400`,
/// the ARCH-0004 §4.5 table value) derives from it.
pub const DEFAULT_RECENCY_HALF_LIFE_DAYS: f32 = 28.0;
