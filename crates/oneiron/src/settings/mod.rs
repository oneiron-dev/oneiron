//! Backend settings data models.

pub mod model_versioning;

pub use model_versioning::{
    DEFAULT_MODEL_STACK_CURRENT_ID, DEFAULT_MODEL_STACK_V1_ID, ModelStack, ModelStackDeprecation,
    ModelStackDeprecationStage, ModelStackDeprecationStatus, ModelStackDisclosure, ModelStackId,
    ModelStackIdError, ModelStackModel, ModelStackPreference, ModelStackRegistry,
    ModelStackRegistryError, ModelStackResolution, default_model_stack_registry,
};
