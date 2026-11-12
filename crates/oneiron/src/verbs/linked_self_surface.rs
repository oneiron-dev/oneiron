//! The verb table is closed over the linked `self.*` operations, checked at
//! build time: every direct import a guest tier links under `self.`, and
//! every agent-authoring import, is a generated verb row, or (for a `self.*`
//! import only) an exact-name entry of
//! [`LINKED_SELF_OPERATION_EXEMPTIONS`]. `tests/linked_self_verb_surface.rs`
//! is the diagnostic form, which also reads the code-mode catalog and names
//! every gap.

use super::{AgentVerb, RunVerb};
use crate::store::sandbox_contract::{
    LINKED_SELF_OPERATION_EXEMPTIONS, SandboxBoundaryContract, SandboxGuestTier,
};
use crate::store::sandbox_import::SandboxImportClass;

/// Byte equality, which a const context can run.
const fn same(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn is_self(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 5
        && bytes[0] == b's'
        && bytes[1] == b'e'
        && bytes[2] == b'l'
        && bytes[3] == b'f'
        && bytes[4] == b'.'
}

const fn has_row(name: &str) -> bool {
    let mut index = 0;
    while index < AgentVerb::ALL.len() {
        if same(AgentVerb::ALL[index].as_str(), name) {
            return true;
        }
        index += 1;
    }
    index = 0;
    while index < RunVerb::ALL.len() {
        if same(RunVerb::ALL[index].as_str(), name) {
            return true;
        }
        index += 1;
    }
    false
}

const fn is_exempt(name: &str) -> bool {
    let mut index = 0;
    while index < LINKED_SELF_OPERATION_EXEMPTIONS.len() {
        if same(LINKED_SELF_OPERATION_EXEMPTIONS[index].0, name) {
            return true;
        }
        index += 1;
    }
    false
}

const _: () = {
    let tiers = [
        SandboxGuestTier::FirstPartyDreamer,
        SandboxGuestTier::Foreign,
        SandboxGuestTier::Untrusted,
    ];
    let mut tier = 0;
    while tier < tiers.len() {
        let imports = SandboxBoundaryContract::for_tier(tiers[tier]).linked_imports();
        let mut index = 0;
        while index < imports.len() {
            let import = imports[index];
            let authoring = matches!(import.class(), SandboxImportClass::AgentAuthoring);
            if authoring || is_self(import.name()) {
                assert!(
                    has_row(import.name()) || (!authoring && is_exempt(import.name())),
                    "a linked self.* or agent-authoring operation has no verb row or named exemption"
                );
            }
            index += 1;
        }
        tier += 1;
    }
};
