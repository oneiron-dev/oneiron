//! The AGENT_DEF body's pinned MessagePack keys, by name: the body, model
//! entry, memory profile, budget split, skill dependency and MCP reference
//! sub-maps, the scope discriminants, the output-decay sub-map and the
//! verbatim-pin observation default.

use crate::write_envelope::skill_record::SKILL_DEPENDENCY_KEYS;

/// The pinned sub-map keys for a profile's `output_decay`, in encode order.
pub const OUTPUT_DECAY_KEYS: [&str; 2] = ["overview_after_turns", "stub_after_turns"];

/// Bytes of one verbatim pin past which a put asks (the length it once
/// refused past); a pin of any length is kept, as any number of pins is.
pub const MAX_MEMORY_PROFILE_VERBATIM_PIN_BYTES: usize = 1024;

pub const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];

pub const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

pub const SCOPE_ALL: &str = "all";

pub const SCOPE_BASE: &str = "base";

pub const SCOPE_WORLD: &str = "world";
