//! Moved from `crates/oneiron/src/verbs/shared_members.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One of the caller's own invitations, by the id its `MemberInvited`
/// receipt named.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub invitation: String,
}

/// `vault.members.accept_with_credential`'s input: the invitee's own invitation
/// and the regular credential's required expiry (Unix seconds). The device key
/// comes only from the verified invitation request, never from this input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationAcceptWithCredentialRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub invitation: String,
    pub expires_at: u64,
}

/// `vault.members.withdraw_invitation`'s input: the invitee's PERSON id, hex,
/// and the invitation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedInvitationWithdrawRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub member: String,
    pub invitation: String,
}

/// `vault.shared.erase_ask`'s input: the record the asker wants erased,
/// entity id hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAskRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub record: String,
}

/// `vault.shared.close_erase_ask`'s input: `erased` when the Owner erased the
/// record, naming with `act_id` the `erase` act they started where the veto
/// window applied; else declined.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedEraseAskCloseRequest {
    pub ask_id: String,
    pub erased: bool,
    #[serde(default)]
    pub act_id: Option<String>,
}

/// `vault.members.invitation_slip`'s input: the caller's own pending
/// invitation. It names no key: the invitation binds the key of the
/// independent credential the request came on (FIX 8745).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvitationSlipRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub invitation: String,
}

/// `vault.members.invitation_code`'s input: the invitee's PERSON id, hex,
/// and their pending invitation.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvitationCodeRequest {
    #[serde(with = "crate::federation::vault_id_decimal")]
    #[schemars(with = "String")]
    pub vault_id: u64,
    pub member: String,
    pub invitation: String,
}

/// `vault.guests.mint_slip`'s input: the Ask or active Connect guest's FEDERATION_GRANT, the
/// public key (64 hex) the guest generated on their own device, and when the
/// slip ends (Unix seconds).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestSlipMintRequest {
    pub grant_ref: EntityId,
    /// The guest's key. An Ask guest's grant that kept the key their ask
    /// carried binds that one, and this may be absent (FIX-LIST 1978).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<String>,
    pub expires_at: u64,
    /// The owner's cap on whom the slip may message (FIX 3899), signed into
    /// it: `parent`, `subtree`, `project` or `vault`. A guest runs in no
    /// dispatch, so any reach narrower than `vault` reaches the vault's
    /// owners only. Absent is `vault`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<oneiron_authority::authority::CommReach>,
}

/// `vault.guests.mint_slip`'s answer: the slip credential for the guest, who
/// proves each request with their own key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestSlipMinted {
    /// The slip id, hex.
    pub slip_id: String,
    /// The `v2.slip.` credential.
    pub slip: String,
    pub expires_at: u64,
}
