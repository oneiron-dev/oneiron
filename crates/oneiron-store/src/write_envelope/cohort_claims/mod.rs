//! Cohort membership, stage, contact suppression and jurisdiction claim vocabulary.

pub mod codec;
mod types;

pub use self::codec::{
    decode_campaign_member_value, decode_crm_stage_value, encode_campaign_member_value,
    encode_comm_bounce_value, encode_crm_stage_value, encode_do_not_contact_value,
    normalize_campaign_pack_token,
};
pub use self::codec::{
    decode_member_recorded_exit, encode_member_recorded_exit,
    validate_campaign_pack_claim_structure,
};
pub use self::types::*;

pub mod ladder;
pub mod snooze_policy;
pub mod suppression;
