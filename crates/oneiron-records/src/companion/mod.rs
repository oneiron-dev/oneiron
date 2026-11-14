pub use crate::companion::persona::PersonaInputBasis;
pub use crate::companion::persona::PersonaMadeBy;
pub(crate) use oneiron_store::serialize::person_identity::validated_persona_baseline;
pub use oneiron_store::write_envelope::companion_subject::CompanionExpression;
pub use oneiron_store::write_envelope::companion_subject::CompanionScope;
pub use oneiron_store::write_envelope::companion_subject::CompanionSubject;
pub use oneiron_store::write_envelope::companion_subject::CompanionSubjectKind;
pub use oneiron_store::write_envelope::companion_subject::CompanionTaskKey;
pub use oneiron_store::write_envelope::companion_task_kind::CompanionTaskKind;
pub(crate) use oneiron_store::write_envelope::person_identity::body_fields as persona_body_fields;
pub(crate) use oneiron_store::write_envelope::person_identity::is_identity_facet_body;

pub mod persona;
