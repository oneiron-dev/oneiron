//! Single-use pairing links bind a throwaway key and mint one log-backed slip.
use super::*;
use crate::Vault;
use crate::error::Result;
use crate::federation::{OrgAdminPolicy, Scope};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use serde::{Deserialize, Serialize};

/// One outstanding single-use pairing/enrollment link. Key: hex64 (keyed hash of the code).
const PAIRING_PENDING: SideTable<String, PairingPending, LegacyJson> =
    SideTable::new(&side_table::AUTHORITY_PAIRING_PENDING);
/// The facet a paired credential's writes are born in, as the owner named it
/// on the link. Key: the slip id as hex64 (a SyncState key is text).
const PAIRED_WRITE_FACET: SideTable<String, crate::EntityId, Raw> =
    SideTable::new(&side_table::AUTHORITY_PAIRING_WRITE_FACET);

/// The [`PAIRED_WRITE_FACET`] key of a slip id.
fn write_facet_key(slip_id: &[u8; 32]) -> String {
    slip_id.iter().map(|byte| format!("{byte:02x}")).collect()
}
/// Immutable one-time organization-administration power grant. Key: hex32 (org_ref).
const ORG_ADMIN_POLICY: SideTable<String, OrgAdminPolicy, LegacyJson> =
    SideTable::new(&side_table::ORG_ADMIN_POLICY);

/// Pairing descriptor is public liveness, not a credential or authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDescriptor {
    pub protocol: String,
    pub slip_version: u8,
    pub binding: String,
    pub pairing_endpoint: String,
}
impl Default for PairingDescriptor {
    fn default() -> Self {
        Self {
            protocol: "oneiron-pairing".into(),
            slip_version: 2,
            binding: "ed25519".into(),
            pairing_endpoint: "/v1/core/pairing/redeem".into(),
        }
    }
}
/// A link/QR payload. The code is random and stored only as a keyed hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingLink {
    pub code: String,
    pub expires_at: u64,
    /// The checkpoint pin's challenge and digest, when the vault has an
    /// attested checkpoint (OF-469): the owner delivers them with the code,
    /// and the joining device checks the pin redeem returns against them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<PairingPinRef>,
    /// Whom the slip this link pairs may message (FIX 3899): the reach the
    /// owner fixed on the link, `vault` when he named none.
    pub comm: super::CommReach,
}
/// What an owner-delivered link says of the checkpoint pin the link keeps: the
/// link's fresh single-use challenge and the pin's digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPinRef {
    pub challenge: [u8; 32],
    pub digest: [u8; 32],
}
impl PairingPinRef {
    /// The reference to `pin`: its challenge and digest.
    pub fn of(pin: &AuthorityCheckpointPin) -> Result<Self> {
        Ok(Self {
            challenge: pin.challenge,
            digest: pin.digest()?,
        })
    }
    /// Whether `pin` is exactly the pin this reference names.
    pub fn names(&self, pin: &AuthorityCheckpointPin) -> bool {
        Self::of(pin).is_ok_and(|named| named == *self)
    }
}
/// What redeeming a link gives: the slip, the machine it enrolled, and the
/// checkpoint pin the link kept, for the joining device to check.
pub struct PairingRedeemed {
    pub slip: CapabilitySlip,
    pub machine: Option<FoldedMachine>,
    pub pin: Option<AuthorityCheckpointPin>,
    /// The owner who made the link, as the link recorded it.
    pub(crate) link_owner: Option<crate::EntityId>,
    /// The link paired again a machine the roster already holds, credential
    /// only (FIX 8636): `machine` is its standing as it was, and nothing
    /// joined the roster.
    pub re_paired: bool,
}
/// Owner-approved identity constraints. Redemption can choose a connection key,
/// but cannot replace these claims or add organization authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingPrincipal {
    pub holder_ref: Option<String>,
    pub actor_class: Option<String>,
    pub org_ref: Option<String>,
    /// The facet (hex id) the credential's writes are born in, when its
    /// scope reads several: one of them. With none named, the smallest. The
    /// slip does not carry it; redemption keeps it beside the slip's id
    /// ([`Vault::paired_write_facet`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_facet: Option<String>,
    /// Whom the paired slip may message (FIX 3899): the owner sets it when
    /// he makes the link, and redemption copies it into the slip's signed
    /// claims; the redeemer never picks it. `None` is the vault-wide reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<super::CommReach>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingPending {
    expires_at: u64,
    slip_lifetime_secs: u64,
    scope: Scope,
    host_key: [u8; 32],
    principal: PairingPrincipal,
    /// The owner's approval of the machine this link adds: his act and his
    /// answer; redemption must enrol that machine and cannot change either
    /// (mesh PR1b C2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    machine: Option<PendingMachine>,
    /// The checkpoint pin the link hands the joining device (OF-469).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pin: Option<AuthorityCheckpointPin>,
    /// The owner who made the link, revalidated when it was made. Its
    /// holder's OpenAI proxy is admitted under that owner (ARCH-0028).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<crate::EntityId>,
}
/// The owner's approval a single-use machine link keeps (mesh PR1b C2): his
/// act's owner, by, surface and kind, and his answer. Redemption fills the
/// act's target (the redeeming machine) and `seen` (its revision on the
/// carrier, zero for a new machine), and the carrier signs.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingMachine {
    owner: crate::EntityId,
    by: ActBy,
    surface: ActSurface,
    kind: OwnerActKind,
    ownership: MachineOwnership,
}

/// Crockford base32: no `I`, `L`, `O` or `U`, so a code survives being read
/// aloud or typed from a screen.
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 8;
const CODE_TTL_SECS: u64 = 60 * 60;
const CODE_HASH_CONTEXT: &str = "oneiron/pairing-code/v1/hash";

mod code;
mod issue;
mod principal;
mod re_pairing;
mod redeem;

pub use code::{
    format_pairing_link, format_pinned_pairing_link, pairing_binding_transcript,
    pairing_binding_transcript_pinned, parse_pairing_link, parse_pinned_pairing_link,
};
pub use re_pairing::machine_possession_transcript;
