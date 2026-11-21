//! What a phone line's agent can see while on a call: the value of
//! `voice.phone.reach`, one choice per phone line (VOICE-PHONE-AGENT-REACH
//! R2). By default the agent sees only this caller's own history and the
//! documents the owner picks; or the whole vault; or a custom scope the owner
//! defines or an agent proposes. Under the whole vault the agent may repeat
//! what other callers said.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::setting::SettingValue;
use serde::{Deserialize, Serialize};

/// The most documents the default preset names.
const DOCUMENTS_MAX: usize = 256;

/// What a phone line's agent can see while on a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "preset", rename_all = "snake_case", deny_unknown_fields)]
pub enum PhoneReach {
    /// This caller's own history and the documents the owner picked.
    Default {
        /// The picked documents, each a canonical 32-char lower hex entity id.
        #[serde(default)]
        documents: Vec<String>,
    },
    /// Everything the line agent's own credential reads, other callers' calls included.
    WholeVault,
    /// A scope the owner defines or an agent proposes (it takes share_scope's place).
    Custom {
        /// The custom scope.
        scope: Scope,
        /// Whether the scope alone decides, other callers' calls included. Off
        /// (the default), a marked phone-thread row reads only in the current
        /// caller's thread, as under the default preset; on, the agent may
        /// repeat what other callers said (REACH-CUSTOM-CALLER-RULE = A,
        /// Engine 16 Nov 04:16).
        #[serde(default)]
        include_other_callers: bool,
    },
}

impl SettingValue for PhoneReach {
    /// Every picked document parses as a canonical lower hex entity id; the
    /// list is stored sorted and deduplicated, at most [`DOCUMENTS_MAX`]
    /// entries.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an entry that is no canonical entity id, or for a
    /// list past the cap.
    fn check(self) -> Result<Self> {
        let PhoneReach::Default { mut documents } = self else {
            return Ok(self);
        };
        for entry in &documents {
            let parses = EntityId::from_hex(entry).is_ok_and(|id| id.to_hex() == *entry);
            if !parses {
                return Err(Error::InvalidConfig(format!(
                    "a picked document is a canonical 32-char lower hex entity id; `{entry}` is none"
                )));
            }
        }
        documents.sort();
        documents.dedup();
        if documents.len() > DOCUMENTS_MAX {
            return Err(Error::InvalidConfig(format!(
                "a line's reach names at most {DOCUMENTS_MAX} documents"
            )));
        }
        Ok(PhoneReach::Default { documents })
    }
}

/// The catalogue default: this caller's own history, no picked documents.
pub(crate) fn reach_default() -> PhoneReach {
    PhoneReach::Default {
        documents: Vec::new(),
    }
}

/// Whether `a` is at least as tight as `b`: anything is at least as tight as
/// the whole vault; the whole vault is tighter than nothing but itself; a
/// default is tighter than a default whose documents cover its own; a custom
/// is tighter than a custom its scope narrows, unless it includes other
/// callers and the other does not (turning that on is a loosening the owner
/// confirms). A default and a custom are incomparable either way, so an
/// agent's flip between them always asks.
pub(crate) fn reach_tighter(a: &PhoneReach, b: &PhoneReach) -> bool {
    match (a, b) {
        (_, PhoneReach::WholeVault) => true,
        (PhoneReach::WholeVault, _) => false,
        (PhoneReach::Default { documents: narrow }, PhoneReach::Default { documents: wide }) => {
            narrow.iter().all(|id| wide.contains(id))
        }
        (
            PhoneReach::Custom {
                scope: narrow,
                include_other_callers: narrow_includes,
            },
            PhoneReach::Custom {
                scope: wide,
                include_other_callers: wide_includes,
            },
        ) => narrow.is_narrowing_of(wide) && (!*narrow_includes || *wide_includes),
        _ => false,
    }
}

impl PhoneReach {
    /// The picked documents as entity ids. `check` guarantees they parse, so
    /// none is skipped; on a parse failure the answer is empty, never more.
    /// A whole-vault or custom reach names no documents.
    #[must_use]
    pub fn documents(&self) -> Vec<EntityId> {
        let PhoneReach::Default { documents } = self else {
            return Vec::new();
        };
        let mut ids = Vec::with_capacity(documents.len());
        for entry in documents {
            let Ok(id) = EntityId::from_hex(entry) else {
                return Vec::new();
            };
            ids.push(id);
        }
        ids
    }
}
