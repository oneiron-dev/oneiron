//! ARCH-0028's registration-time authority tiers for an outside agent, as
//! stored authority: the credential scopes its bearer carries, the verbs its
//! owner agent grant lists, and the agent's ceiling. `oneiron token agent`
//! and the vault's OAuth sign-in (FIX 4902) both map a tier through here, so
//! one tier means the same authority on every door that admits an agent.

#[doc(hidden)]
pub use oneiron_verb_wire::authority::agent_tier::AgentTier;
