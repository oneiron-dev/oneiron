//! Site-skill exposures (FIX 11436): the rows live in
//! `store::site_skill_exposure`; this module keeps the skill attribution paths.
pub use crate::store::site_skill_exposure::{
    SiteSkillExposure, record_site_exposures, site_exposed,
};
