//! Moved from `crates/oneiron/src/secret_custody/reveal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::secret_custody::reveal::types::SecretRevealCause;
pub use crate::secret_custody::reveal::types::SecretRevealReceipt;
pub use crate::secret_custody::reveal::types::SecretRevealState;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::secret_record::CustodyClass;
pub use oneiron_verb_wire::secret_custody::reveal::types::RevealGrantScope;

/// The life of the T1 lease a delivered reveal stamps, and of the lease a
/// PERSON reveal keeps on its row (FIX 11683), in seconds. Canon names none.
pub const REVEAL_LEASE_TTL_SECS: u64 = 900;

/// The envelope selector of a reveal asked outside any project: a grant for
/// it covers reveals that name no project, and no other.
pub const NO_PROJECT_SELECTOR: &str = "project:none";

/// The version of the engine's disclosure line, bound into the once digest:
/// a change of wording is a different ask.
pub const DISCLOSURE_VERSION: &str = "secret_reveal.disclosure.v2";

/// What the disclosure line names when no host named the agent's model
/// provider (an external HTTP or MCP agent, or a model no ladder served).
/// One constant, so a ruling changes one line.
pub const UNKNOWN_PROVIDER_DISCLOSURE: &str =
    "this agent's model provider, which this host does not know";

/// Domain of the digest an owner's answer authorizes.
pub const ONCE_DIGEST_DOMAIN: &[u8] = b"oneiron.secret_reveal.once.v1";

/// The reader of an agent's reveal; the owner's own read is `owner`.
pub const READER_AGENT: &str = "agent";

/// What "this connection" is: the asking agent's own actor. The engine holds
/// no connection entity; one agent identity is one paired client.
pub fn reveal_connection(agent: &EntityId) -> String {
    format!("agent:{}", agent.to_hex())
}

/// What "this class" is: the record's custody class.
pub fn reveal_class(class: CustodyClass) -> String {
    format!("secret:{}", class.as_str())
}

/// What "this project" is: the project the run works in, or
/// [`NO_PROJECT_SELECTOR`].
pub fn project_selector(project: Option<&EntityId>) -> String {
    project.map_or_else(
        || NO_PROJECT_SELECTOR.to_owned(),
        |project| format!("project:{}", project.to_hex()),
    )
}

/// The engine's own line on where a revealed value goes, in words no agent
/// wrote: `what` (such as "Revealing sc12 sends its value") goes on to name
/// the connection and the provider. It names no value.
pub fn disclosure_line(what: &str, connection: &str, provider: Option<&str>) -> String {
    match provider {
        Some(provider) => format!(
            "{what} through {connection} to {provider}; {provider} and its logs then hold it."
        ),
        None => format!(
            "{what} through {connection} to {UNKNOWN_PROVIDER_DISCLOSURE}; that provider and \
             its logs then hold it."
        ),
    }
}
pub mod file;
pub mod types;
