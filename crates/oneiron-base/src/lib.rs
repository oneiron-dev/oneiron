//! The base layer of the oneiron engine: modules that name nothing above them.
//! The `oneiron` crate depends on this one and re-exports each module at its old
//! `oneiron::<module>` path, and each root fn at its old `crate::` path.
//! Many modules here are paths onto items defined in `oneiron-contracts`,
//! `oneiron-retrieval` and `oneiron-model`, so the modules moved down from
//! `oneiron` keep their `crate::<module>` paths.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod analyzer;
pub mod config;
pub mod distance;
pub mod edge;
pub mod entity_id;
pub mod error;
pub mod extraction_eval;
pub mod fusion;
pub mod human_task_followup;
pub mod learning_estimate;
pub mod learning_ranking;
pub mod limits;
pub mod live_rows;
pub mod message_body_fields;
pub mod msgpack_shape;
pub mod panic_report;
pub mod posterior;
pub mod registry;
pub mod request_limits;
pub mod retrieval_quality;
pub mod tokenizer;
pub mod work_line;

pub fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
