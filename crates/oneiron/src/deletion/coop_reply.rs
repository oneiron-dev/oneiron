//! The recipient's one-line answer to a courtesy deletion ask (OF-273): its
//! owner acted on the ask, or declined it. The answer says nothing about what
//! was kept or deleted, and it is no deletion proof.

use rmpv::Value;

use super::coop_request::{
    binary, decode, encode, envelope_signature, fields, invalid, signature_value, uint,
};
use crate::Vault;
use crate::authority::{AuthorityKey, AuthoritySignature, verify_authority_signature};
use crate::error::Result;

/// Domain for a recipient's answer to an ask.
pub const COOP_DELETION_REPLY_DOMAIN: &[u8] = b"oneiron/deletion/coop-reply/v1";
/// Wire schema version.
pub const COOP_DELETION_REPLY_SCHEMA_VERSION: u64 = 1;
/// Exact canonical body keys, in wire order.
pub const COOP_DELETION_REPLY_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "pact_id",
    "requester_vault_id",
    "responder_vault_id",
    "nonce",
    "outcome",
    "ts",
];

/// What the recipient's owner did with an ask, as the requester learns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeDeletionReplyOutcome {
    /// The owner chose from the menu: delete, redact, restrict, retain or hold.
    Acknowledged,
    /// The owner declined, with a reason code and a review date kept on their side.
    Declined,
}

impl CooperativeDeletionReplyOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::Declined => "declined",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "acknowledged" => Ok(Self::Acknowledged),
            "declined" => Ok(Self::Declined),
            _ => Err(invalid()),
        }
    }
}

/// The answer to one ask, named by its pact and nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionReply {
    pub pact_id: [u8; 32],
    /// The vault that asked.
    pub requester_vault_id: [u8; 32],
    /// The vault that answers.
    pub responder_vault_id: [u8; 32],
    pub nonce: [u8; 16],
    pub outcome: CooperativeDeletionReplyOutcome,
    pub ts: u64,
}

/// Authenticated answer bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCooperativeDeletionReply {
    pub body: CooperativeDeletionReply,
    pub signature: AuthoritySignature,
}

/// Encodes the canonical answer body.
pub fn encode_cooperative_deletion_reply_body(body: &CooperativeDeletionReply) -> Result<Vec<u8>> {
    if body.pact_id == [0; 32]
        || body.requester_vault_id == [0; 32]
        || body.responder_vault_id == [0; 32]
        || body.nonce == [0; 16]
    {
        return Err(invalid());
    }
    let values = [
        Value::from(COOP_DELETION_REPLY_SCHEMA_VERSION),
        Value::Binary(body.pact_id.to_vec()),
        Value::Binary(body.requester_vault_id.to_vec()),
        Value::Binary(body.responder_vault_id.to_vec()),
        Value::Binary(body.nonce.to_vec()),
        Value::from(body.outcome.as_str()),
        Value::from(body.ts),
    ];
    encode(&Value::Map(
        COOP_DELETION_REPLY_BODY_KEYS
            .iter()
            .zip(values)
            .map(|(k, v)| (Value::from(*k), v))
            .collect(),
    ))
}

/// Encodes an answer as the two-key body/signature envelope.
pub fn encode_signed_cooperative_deletion_reply(
    reply: &SignedCooperativeDeletionReply,
) -> Result<Vec<u8>> {
    let body = encode_cooperative_deletion_reply_body(&reply.body)?;
    if !verify_authority_signature(
        &reply.signature,
        &[COOP_DELETION_REPLY_DOMAIN, &body].concat(),
    ) {
        return Err(invalid());
    }
    encode(&Value::Map(vec![
        (Value::from("body"), Value::Binary(body)),
        (Value::from("signature"), signature_value(&reply.signature)),
    ]))
}

/// Verifies an answer against the key the requester pinned for its peer.
pub fn decode_and_verify_cooperative_deletion_reply(
    bytes: &[u8],
    expected_signer: &AuthorityKey,
) -> Result<CooperativeDeletionReply> {
    let value = decode(bytes)?;
    let outer = fields(&value, &["body", "signature"])?;
    let Value::Binary(body_bytes) = outer[0] else {
        return Err(invalid());
    };
    let signature = envelope_signature(outer[1])?;
    if &signature.public_key != expected_signer
        || !verify_authority_signature(
            &signature,
            &[COOP_DELETION_REPLY_DOMAIN, body_bytes].concat(),
        )
    {
        return Err(invalid());
    }
    let body_value = decode(body_bytes)?;
    let f = fields(&body_value, &COOP_DELETION_REPLY_BODY_KEYS)?;
    if uint(f[0])? != COOP_DELETION_REPLY_SCHEMA_VERSION {
        return Err(invalid());
    }
    let body = CooperativeDeletionReply {
        pact_id: binary(f[1])?,
        requester_vault_id: binary(f[2])?,
        responder_vault_id: binary(f[3])?,
        nonce: binary(f[4])?,
        outcome: CooperativeDeletionReplyOutcome::parse(f[5].as_str().ok_or_else(invalid)?)?,
        ts: uint(f[6])?,
    };
    if encode_cooperative_deletion_reply_body(&body)? != *body_bytes {
        return Err(invalid());
    }
    Ok(body)
}

impl Vault {
    /// Signs this vault's answer to an ask its pact's peer sent.
    pub fn sign_cooperative_deletion_reply<S>(
        &self,
        pact_id: &[u8; 32],
        nonce: [u8; 16],
        outcome: CooperativeDeletionReplyOutcome,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<SignedCooperativeDeletionReply>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        let fold = self.authority_fold()?;
        let pact = fold.federation_pacts.get(pact_id).ok_or_else(invalid)?;
        let body = CooperativeDeletionReply {
            pact_id: *pact_id,
            requester_vault_id: pact.peer_vault_id,
            responder_vault_id: fold.vault_id.ok_or_else(invalid)?,
            nonce,
            outcome,
            ts: crate::unix_seconds_now(),
        };
        let bytes = encode_cooperative_deletion_reply_body(&body)?;
        let transcript = [COOP_DELETION_REPLY_DOMAIN, &bytes].concat();
        let signature = AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: signer(&transcript)?,
        };
        if !verify_authority_signature(&signature, &transcript) {
            return Err(invalid());
        }
        Ok(SignedCooperativeDeletionReply { body, signature })
    }
}
