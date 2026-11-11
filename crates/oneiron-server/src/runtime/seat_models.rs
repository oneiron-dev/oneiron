//! The model door of a seat run (FIX 15702 slice 1; ARCH-0069
//! `#door-sign-loopback`, OSH p6): an official CLI seat's model calls go
//! through this host's loopback listener, and the provider key stays in the
//! vault's custody (T0), read at the custody door for each call and handed
//! to the credential broker with that one request.
//!
//! The operator binds door slots (`[runtime.seat_model_providers]`): each
//! names a `[models.providers.<name>]` entry with a `key_secret` and the
//! exact wire models a seat may ask for through it. A run reaches the slots
//! whose provider key its pinned secret manifest declares. For such a run
//! the host mints a fresh reference per slot, keeps only its digest in the
//! run's registration, and hands the CLI the reference and the slot's
//! loopback URL in the variables an SDK reads (`ANTHROPIC_BASE_URL` and
//! `ANTHROPIC_API_KEY`, `OPENAI_BASE_URL` and `OPENAI_API_KEY`). The
//! reference is a bearer capability to this door alone, for this run's
//! claim: never a provider key, a slip or a grant. A process that copies it
//! can spend it while the run's registration and claim stand, and no longer.
//!
//! The door serves OpenAI chat completions and Anthropic Messages, whole or
//! as server-sent events (slice 2), with Claude Code's `?beta=true` on
//! Messages.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// The path the door's routes sit under, `/v1/seat/model/{slot}/…`.
pub const SEAT_MODEL_PATH: &str = "/v1/seat/model";

/// The prefix of a model door reference, so it is never read as a slip
/// (`v2.slip.`) or a provider key.
pub const SEAT_MODEL_REFERENCE_PREFIX: &str = "oneiron-seat-model.";

/// Whether `name` may name a door slot: it rides the door's URL path, so
/// ASCII letters, digits, `.`, `_` and `-` alone.
#[must_use]
pub fn is_seat_model_slot_name(name: &str) -> bool {
    super::is_helper_destination_name(name)
}

/// One door slot the operator binds, by its name in
/// `[runtime.seat_model_providers]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatModelBinding {
    /// The `[models.providers.<name>]` entry the slot sends through: its
    /// `key_secret`, base URL, kind, headers and timeout. It must name a
    /// `key_secret`, and its kind must speak OpenAI chat or Anthropic
    /// Messages.
    pub provider: String,
    /// The exact wire model names a seat may ask for through the slot. A
    /// request naming any other is refused; an empty list offers nothing.
    pub models: BTreeSet<String>,
}

/// The wire protocol a slot speaks, from its provider's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatModelProtocol {
    /// OpenAI chat completions, `POST …/v1/chat/completions`.
    OpenAiChat,
    /// Anthropic Messages, `POST …/v1/messages`.
    AnthropicMessages,
}

impl SeatModelProtocol {
    /// The endpoint under a slot's URL a seat posts this protocol to.
    #[must_use]
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::OpenAiChat => "/v1/chat/completions",
            Self::AnthropicMessages => "/v1/messages",
        }
    }
}

/// One slot as a run's registration holds it: what the door checks each
/// request against, and the digest of the run's reference to it. The
/// reference itself is never kept.
#[derive(Clone)]
pub struct SeatModelSlot {
    /// The provider name the slot was bound to at registration. A request
    /// is refused once the host's provider of that name no longer sends
    /// with `secret`.
    pub provider: String,
    /// The custody name of the provider key, as the run's slip records it.
    pub secret: String,
    pub protocol: SeatModelProtocol,
    /// The wire models a request may name.
    pub models: BTreeSet<String>,
    reference: [u8; 32],
}

impl fmt::Debug for SeatModelSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatModelSlot")
            .field("provider", &self.provider)
            .field("secret", &self.secret)
            .field("protocol", &self.protocol)
            .field("models", &self.models)
            .finish_non_exhaustive()
    }
}

impl SeatModelSlot {
    /// The slot for a reference minted by [`mint_reference`], kept by its
    /// digest alone.
    #[must_use]
    pub fn new(
        provider: String,
        secret: String,
        protocol: SeatModelProtocol,
        models: BTreeSet<String>,
        reference: &SeatModelReference,
    ) -> Self {
        Self {
            provider,
            secret,
            protocol,
            models,
            reference: reference.digest,
        }
    }

    /// Whether `presented` is this slot's reference, compared in constant
    /// time on its digest.
    #[must_use]
    pub fn presented(&self, presented: &str) -> bool {
        bool::from(digest(presented)[..].ct_eq(&self.reference[..]))
    }
}

/// A fresh reference to one slot: its text, for the CLI's environment
/// alone, and its digest, for the registration.
pub struct SeatModelReference {
    text: Zeroizing<String>,
    digest: [u8; 32],
}

impl fmt::Debug for SeatModelReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SeatModelReference(..)")
    }
}

/// Mints a fresh reference: 32 random bytes from the OS, as hex, under
/// [`SEAT_MODEL_REFERENCE_PREFIX`].
#[must_use]
pub fn mint_reference() -> SeatModelReference {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand_core::OsRng.fill_bytes(&mut bytes[..]);
    let mut text = Zeroizing::new(String::with_capacity(
        SEAT_MODEL_REFERENCE_PREFIX.len() + 64,
    ));
    text.push_str(SEAT_MODEL_REFERENCE_PREFIX);
    for byte in bytes.iter() {
        // Written in place: no unwiped copy of the hex is made.
        let _ = write!(text, "{byte:02x}");
    }
    let digest = digest(&text);
    SeatModelReference { text, digest }
}

fn digest(reference: &str) -> [u8; 32] {
    *blake3::hash(reference.as_bytes()).as_bytes()
}

/// The environment a seat CLI's SDK reads its model endpoint and key from
/// (FIX 15702): for each protocol one slot speaks, that slot's loopback URL
/// and the run's reference to it. A protocol two slots speak gets neither,
/// since one variable cannot name both. Set on the CLI's process after the
/// seat removes the inherited vendor credentials, so the reference is the
/// one key the CLI's own SDK holds.
#[derive(Clone)]
pub struct SeatModelEnv {
    vars: Vec<(&'static str, Zeroizing<String>)>,
}

impl fmt::Debug for SeatModelEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeatModelEnv")
            .field(
                "vars",
                &self.vars.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl SeatModelEnv {
    /// The environment for a run calling back on `origin`, with its
    /// references to `slots`, by their names.
    #[must_use]
    pub fn new(
        origin: &str,
        slots: &BTreeMap<String, (SeatModelProtocol, SeatModelReference)>,
    ) -> Self {
        let mut vars = Vec::new();
        for protocol in [
            SeatModelProtocol::AnthropicMessages,
            SeatModelProtocol::OpenAiChat,
        ] {
            let speaking: Vec<_> = slots
                .iter()
                .filter(|(_, (spoken, _))| *spoken == protocol)
                .collect();
            let [(name, (_, reference))] = speaking.as_slice() else {
                if speaking.len() > 1 {
                    tracing::warn!(
                        ?protocol,
                        "two seat model slots speak one protocol; neither is set in the seat's environment"
                    );
                }
                continue;
            };
            let base = format!("{origin}{SEAT_MODEL_PATH}/{name}");
            // An Anthropic SDK appends `/v1/messages` to its base; an OpenAI
            // SDK appends `/chat/completions` to a base that ends in `/v1`.
            let (base_var, key_var, base) = match protocol {
                SeatModelProtocol::AnthropicMessages => {
                    ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", base)
                }
                SeatModelProtocol::OpenAiChat => {
                    ("OPENAI_BASE_URL", "OPENAI_API_KEY", format!("{base}/v1"))
                }
            };
            vars.push((base_var, Zeroizing::new(base)));
            vars.push((key_var, reference.text.clone()));
        }
        Self { vars }
    }

    /// Whether it sets nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Sets its variables on the CLI's process.
    pub fn apply(&self, command: &mut std::process::Command) {
        for (name, value) in &self.vars {
            command.env(name, value.as_str());
        }
    }
}
