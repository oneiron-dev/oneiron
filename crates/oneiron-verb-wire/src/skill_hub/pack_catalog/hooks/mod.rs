pub use crate::skill_hub::pack_catalog::hooks::author::HookAuthor;
pub use oneiron_store::pack_hook_actor_class::HookActorClass;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub mod author;
