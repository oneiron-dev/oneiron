//! The standard MCP tool annotations each listed tool carries (census L1-11,
//! Engine ruling 2026-11-13 22:39 = A).
//!
//! MCP's `ToolAnnotations` (protocol 2025-03-26 and later) are hints a client
//! may show, or weigh before it asks the person to confirm a call. They are
//! never a grant: the vault checks every call against the caller's own
//! credential, whatever a tool's hints say. Here they come from the act class
//! the tool's verb row states (`act_class` in `scripts/sdk/verbs/<verb>.json`;
//! ARCH-0082 #act-table):
//!
//! | tool | `readOnlyHint` | `destructiveHint` | `openWorldHint` |
//! |---|---|---|---|
//! | `setup`, `read_result`, a `read` verb | true | | |
//! | a `reversible_work` verb (an undo restores it) | false | false | |
//! | a `delete`, `erase`, `vault_delete` or `member_remove` verb | false | true | |
//! | an `outbound_send` or `legal_send` verb | false | | true |
//! | a verb of any other act class | false | | |
//! | an `unstated` verb, `execute_code`, `invoke_action` | no annotations | | |
//!
//! An empty cell is left out, so the protocol's default applies: a tool that
//! is not read-only may destroy and may reach outside the vault. No hint is
//! given that the act class cannot back: a `read` or `reversible_work` verb
//! may still reach outside the vault (a model call, a publish to a git
//! origin), so neither says `openWorldHint` false. `execute_code` and
//! `invoke_action` run whatever the call names, and an `unstated` verb has no
//! proven undo class, so they carry no hints at all.
//!
//! The hints depend on the tool alone, so the listing frozen at registration
//! stays the same bytes for every caller.

use oneiron::check_in::{ActClass, VerbActClass};
use serde::Serialize;

/// One tool's hints, as `tools/list` publishes them under `annotations`.
/// A hint left out is not serialized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    /// The tool does not modify its environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    /// The tool may make an update that is not purely additive; meaningful
    /// only when it is not read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    /// The tool may interact with entities outside the vault.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl McpToolAnnotations {
    /// A tool that only reads.
    pub const READ_ONLY: Self = Self {
        read_only_hint: Some(true),
        destructive_hint: None,
        open_world_hint: None,
    };

    /// A tool that writes, with no further hint.
    const WRITES: Self = Self {
        read_only_hint: Some(false),
        destructive_hint: None,
        open_world_hint: None,
    };

    /// The hints for a verb whose row states `class` (the module table);
    /// `None` for an `unstated` class or a name that is no verb row.
    #[must_use]
    pub const fn for_verb_act_class(class: Option<VerbActClass>) -> Option<Self> {
        let act = match class {
            Some(VerbActClass::Read) => return Some(Self::READ_ONLY),
            Some(VerbActClass::Act(act)) => act,
            Some(VerbActClass::Unstated) | None => return None,
        };
        Some(match act {
            ActClass::ReversibleWork => Self {
                destructive_hint: Some(false),
                ..Self::WRITES
            },
            ActClass::Delete | ActClass::Erase | ActClass::VaultDelete | ActClass::MemberRemove => {
                Self {
                    destructive_hint: Some(true),
                    ..Self::WRITES
                }
            }
            ActClass::OutboundSend | ActClass::LegalSend => Self {
                open_world_hint: Some(true),
                ..Self::WRITES
            },
            ActClass::Spawn
            | ActClass::SpendOverCap
            | ActClass::RoomAdd
            | ActClass::MemberAdd
            | ActClass::Sign
            | ActClass::Billing
            | ActClass::OwnershipTransfer
            | ActClass::KeyRecovery
            | ActClass::SecurityControlDisable
            | ActClass::MassSecretExport
            | ActClass::WorldWiden
            | ActClass::GrantWiden
            | ActClass::GrantWidenOwn => Self::WRITES,
        })
    }
}
