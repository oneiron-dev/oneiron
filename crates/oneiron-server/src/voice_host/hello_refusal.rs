//! A voice hello refused before its call is admitted (`boot`) is answered
//! with one line, `{"op":"refused","code":..,"reason":..}` and a line feed,
//! before the socket closes. Each refusal names its code ([`Refusal`]); a
//! reap pause's line also carries its `bound` and `self_hosted` route.

use std::io;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

/// How long a refused hello's one `refused` line may take to write, as
/// long as a call's own replies may.
const REFUSAL_WRITE: Duration = Duration::from_secs(1);

/// Why a hello was refused before its call was admitted. The socket is
/// answered with one line naming it, `{"op":"refused","code":..,"reason":..}`
/// and a line feed, then closed. A reason is plain text, and never carries a
/// token, a proof, a MAC or a nonce.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub(super) enum Refusal {
    /// A managed vault frozen for reap takes no call.
    #[error("voice: writes are frozen")]
    WritesFrozen,
    /// No hello line came within the five seconds a connection has to say
    /// hello, or the stream closed first.
    #[error("voice: no hello")]
    NoHello,
    /// The first line is not a hello this host reads.
    #[error("voice: not a hello")]
    NotHello,
    /// The hello's credential is missing, mixed with another, or did not
    /// verify.
    #[error("voice: credential")]
    Credential,
    #[error("voice: not a capability slip")]
    NotCapabilitySlip,
    #[error("voice: not the owner's enrolled device")]
    NotEnrolledDevice,
    /// The supervisor's attestation did not verify, sat outside its time
    /// window, or was taken before.
    #[error("voice: managed owner")]
    ManagedOwner,
    /// A managed hello's nonce is missing or not 32 lowercase hex characters.
    #[error("voice: nonce")]
    Nonce,
    #[error("voice: scope")]
    Scope,
    #[error("voice: owner")]
    Owner,
    #[error("voice: principal")]
    Principal,
    #[error("voice: room")]
    Room,
    #[error("voice: roster")]
    Roster,
    /// The room's call has no payer to bill (`PayerFault::Missing`).
    #[error("voice: payer missing")]
    PayerMissing,
    /// The payer's billing account waits on the owners' yes
    /// (`PayerFault::Needed`).
    #[error("voice: payer needed")]
    PayerNeeded,
    #[error("voice: agent not readable")]
    Agent,
    /// The call could not be prepared: a failure of this host, not a
    /// refusal of the caller.
    #[error("voice: unavailable")]
    Unavailable,
}

impl Refusal {
    /// The refusal's code and its plain reason, as its `refused` line names
    /// them.
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::WritesFrozen => (
                "writes_frozen",
                "this hosted vault is paused under its vault lifecycle allocation, a capacity \
                 bound, while the service prepares to reap it; the same call opens once the \
                 reap is aborted or the vault wakes, and works on a self-hosted vault, which \
                 has no service reap limit",
            ),
            Self::NoHello => ("no_hello", "no hello line came within 5 seconds"),
            Self::NotHello => ("not_hello", "the first line is not a hello this host reads"),
            Self::Credential => (
                "credential",
                "the hello's credential is missing, mixed with another, or did not verify",
            ),
            Self::NotCapabilitySlip => (
                "not_capability_slip",
                "the hello's token is not a capability slip",
            ),
            Self::NotEnrolledDevice => (
                "not_enrolled_device",
                "the machine does not stand here as the owner's own enrolled device",
            ),
            Self::ManagedOwner => (
                "managed_owner",
                "the supervisor's attestation did not verify, is outside its 60-second window, \
                 or was already used",
            ),
            Self::Nonce => (
                "nonce",
                "a managed hello needs a fresh nonce of 32 lowercase hex characters",
            ),
            Self::Scope => ("scope", "the credential does not carry read and write"),
            Self::Owner => ("owner", "the caller is not the vault's live owner"),
            Self::Principal => ("principal", "the credential names no person"),
            Self::Room => (
                "room",
                "the room is empty, unknown, or not one the caller reads",
            ),
            Self::Roster => (
                "roster",
                "the roster is empty, padded with spaces, or longer than 128 bytes",
            ),
            Self::PayerMissing => ("payer_missing", "no payer funds a call in this room"),
            Self::PayerNeeded => (
                "payer_needed",
                "the payer's billing account waits on the vault owners' yes; call again once \
                 they answer",
            ),
            Self::Agent => ("agent", "the answering agent is not readable by the caller"),
            Self::Unavailable => ("unavailable", "the call could not be prepared on this host"),
        }
    }
}

/// A [`Refusal`]'s one line on the wire.
#[derive(Serialize)]
struct RefusedLine {
    op: &'static str,
    code: &'static str,
    reason: &'static str,
    /// A reap pause's `bound` and `self_hosted` route, as the managed HTTP
    /// body carries them (L9-61).
    #[serde(flatten)]
    reap_pause: Option<crate::managed::ReapPauseBound>,
}

/// `refusal`'s one `refused` line, its line feed included.
fn refused_line(refusal: Refusal) -> serde_json::Result<Vec<u8>> {
    let (code, reason) = refusal.wire();
    let mut line = serde_json::to_vec(&RefusedLine {
        op: "refused",
        code,
        reason,
        reap_pause: matches!(refusal, Refusal::WritesFrozen)
            .then_some(crate::managed::REAP_PAUSE_BOUND),
    })?;
    line.push(b'\n');
    Ok(line)
}

/// `refusal` as the error its hello's call ends with.
pub(super) fn refused(refusal: Refusal) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, refusal)
}

/// Answers a hello refused before its call was admitted with its one
/// `refused` line ([`Refusal`]); a failure that is no refusal of the caller
/// is answered `unavailable`. A peer that reads nothing holds its own call,
/// and the server's stop, for [`REFUSAL_WRITE`] at most.
pub(super) async fn refuse(stream: &mut UnixStream, error: &io::Error) {
    let refusal = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Refusal>())
        .copied()
        .unwrap_or(Refusal::Unavailable);
    let Ok(line) = refused_line(refusal) else {
        return;
    };
    let _ = tokio::time::timeout(REFUSAL_WRITE, stream.write_all(&line)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reap pause's `refused` line names its capacity bound and the
    /// self-host route, in the shape the managed HTTP body carries (L9-61).
    #[test]
    fn a_reap_pause_hello_line_names_its_capacity_bound_and_the_self_host_route() {
        let line = refused_line(Refusal::WritesFrozen).expect("line");
        assert_eq!(line.last(), Some(&b'\n'));
        let line: serde_json::Value = serde_json::from_slice(&line).expect("json");
        assert_eq!(line["op"], "refused");
        assert_eq!(line["code"], "writes_frozen");
        assert_eq!(
            line["bound"],
            serde_json::json!({
                "kind": "capacity",
                "resource": "vault_lifecycle_allocation",
                "phase": "reap_prepare",
            })
        );
        assert_eq!(
            line["self_hosted"],
            serde_json::json!({"supported": true, "condition": "no_service_reap_limit"})
        );
        let reason = line["reason"].as_str().expect("reason");
        assert!(reason.contains("a capacity bound"), "{reason}");
        assert!(reason.contains("self-hosted vault"), "{reason}");
    }

    /// Any other refusal's line carries no bound.
    #[test]
    fn another_hello_refusal_line_carries_no_bound() {
        let line = refused_line(Refusal::NoHello).expect("line");
        let line: serde_json::Value = serde_json::from_slice(&line).expect("json");
        assert_eq!(line["code"], "no_hello");
        assert!(line.get("bound").is_none(), "{line}");
        assert!(line.get("self_hosted").is_none(), "{line}");
    }
}
