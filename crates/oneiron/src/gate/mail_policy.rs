//! Vault-resident native-mail posture and CID-5 graduation policy rows.
//! Rows from trusted manifests narrow together: vault cap, then holder and
//! identity overlays. A holder cannot widen the vault's boundary.
use super::input::ExternalEffectPolicyRisk;
use crate::counterparty_contact::CounterpartyFirstTouch;
use crate::entity_id::EntityId;
use crate::identity_reputation::{BOUNCE_CONSTRAINED_THRESHOLD, COMPLAINT_CONSTRAINED_THRESHOLD};
use rmpv::Value;

pub(super) const MANIFEST_KEY: &str = "native_mail_policy";
const PRECEDENCE: &str = "nested_narrowing_holder_capped_at_vault";
const KEYS: [&str; 11] = [
    "scope",
    "holder",
    "identity",
    "known_first_touch",
    "cold_posture",
    "max_complaint_rate",
    "max_bounce_rate",
    "max_spam_labels",
    "allowed_attestation",
    "allowed_warmup",
    "precedence",
];

#[derive(Clone, Debug, PartialEq)]
enum Scope {
    Vault,
    Holder(EntityId),
    Identity(EntityId),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MailPolicy {
    scope: Scope,
    known: Vec<CounterpartyFirstTouch>,
    hold_cold: bool,
    pub(crate) max_complaint_rate: f64,
    pub(crate) max_bounce_rate: f64,
    pub(crate) max_spam_labels: u64,
    attestation: Vec<String>,
    warmup: Vec<String>,
}

impl MailPolicy {
    pub(crate) fn frontier_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let scope = match self.scope {
            Scope::Vault => "vault".to_owned(),
            Scope::Holder(id) => format!("holder:{}", id.to_hex()),
            Scope::Identity(id) => format!("identity:{}", id.to_hex()),
        };
        bytes.extend_from_slice(scope.as_bytes());
        bytes.push(u8::from(self.hold_cold));
        bytes.extend_from_slice(&self.max_complaint_rate.to_bits().to_le_bytes());
        bytes.extend_from_slice(&self.max_bounce_rate.to_bits().to_le_bytes());
        bytes.extend_from_slice(&self.max_spam_labels.to_le_bytes());
        for touch in &self.known {
            bytes.extend_from_slice(touch.as_str().as_bytes());
            bytes.push(0);
        }
        for tier in &self.attestation {
            bytes.extend_from_slice(tier.as_bytes());
            bytes.push(0);
        }
        for stage in &self.warmup {
            bytes.extend_from_slice(stage.as_bytes());
            bytes.push(0);
        }
        bytes
    }
    pub(crate) fn is_known(&self, touch: Option<CounterpartyFirstTouch>) -> bool {
        touch.is_some_and(|touch| self.known.contains(&touch))
    }
    pub(crate) fn cold_risk(&self) -> ExternalEffectPolicyRisk {
        if self.hold_cold {
            ExternalEffectPolicyRisk::HoldToProposal
        } else {
            ExternalEffectPolicyRisk::Normal
        }
    }
    pub(crate) fn attestation_earns(&self, tier: &str) -> bool {
        self.attestation.iter().any(|allowed| allowed == tier)
    }
    pub(crate) fn warmup_earns(&self, stage: &str) -> bool {
        self.warmup.iter().any(|allowed| allowed == stage)
    }
    fn restrict(&mut self, other: &Self) {
        self.known.retain(|v| other.known.contains(v));
        self.hold_cold |= other.hold_cold;
        self.max_complaint_rate = self.max_complaint_rate.min(other.max_complaint_rate);
        self.max_bounce_rate = self.max_bounce_rate.min(other.max_bounce_rate);
        self.max_spam_labels = self.max_spam_labels.min(other.max_spam_labels);
        self.attestation.retain(|v| other.attestation.contains(v));
        self.warmup.retain(|v| other.warmup.contains(v));
    }
}

/// Strict manifest decoder: unknown/duplicate keys or malformed axes fail the
/// pack closed instead of substituting a permissive mail policy.
pub(super) fn decode_rows(value: &Value) -> Option<Vec<MailPolicy>> {
    let Value::Array(rows) = value else {
        return None;
    };
    if rows.len() > 64 {
        return None;
    }
    rows.iter().map(decode_row).collect()
}
fn decode_row(value: &Value) -> Option<MailPolicy> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != KEYS.len() {
        return None;
    }
    let mut map = std::collections::BTreeMap::new();
    for (key, value) in entries {
        let name = key.as_str()?;
        if !KEYS.contains(&name) || map.insert(name.to_owned(), value).is_some() {
            return None;
        }
    }
    let field = |name: &str| -> Option<&Value> { map.get(name).copied() };
    if field("precedence")?.as_str()? != PRECEDENCE {
        return None;
    }
    let id = |name| match field(name)? {
        Value::Nil => Some(None),
        value => EntityId::from_hex(value.as_str()?).ok().map(Some),
    };
    let holder = id("holder")?;
    let identity = id("identity")?;
    let scope = match (field("scope")?.as_str()?, holder, identity) {
        ("vault", None, None) => Scope::Vault,
        ("holder", Some(actor), None) => Scope::Holder(actor),
        ("identity", None, Some(sender)) => Scope::Identity(sender),
        _ => return None,
    };
    let names = |name: &str, allowed: &[&str]| -> Option<Vec<String>> {
        let Value::Array(values) = field(name)? else {
            return None;
        };
        if values.len() > allowed.len() {
            return None;
        }
        let mut out = Vec::new();
        for value in values {
            let token = value.as_str()?;
            if !allowed.contains(&token) || out.iter().any(|s| s == token) {
                return None;
            }
            out.push(token.to_owned());
        }
        Some(out)
    };
    let known = names("known_first_touch", &["user_introduction", "inbound_first"])?
        .iter()
        .map(|name| CounterpartyFirstTouch::parse(name))
        .collect::<Option<Vec<_>>>()?;
    let hold_cold = match field("cold_posture")?.as_str()? {
        "hold_to_proposal" => true,
        "normal" => false,
        _ => return None,
    };
    let rate = |name| -> Option<f64> {
        let rate = field(name)?.as_f64()?;
        (rate.is_finite() && (0.0..=1.0).contains(&rate)).then_some(rate)
    };
    Some(MailPolicy {
        scope,
        known,
        hold_cold,
        max_complaint_rate: rate("max_complaint_rate")?,
        max_bounce_rate: rate("max_bounce_rate")?,
        max_spam_labels: field("max_spam_labels")?.as_u64()?,
        attestation: names("allowed_attestation", &["a", "b", "c", "unknown"])?,
        warmup: names(
            "allowed_warmup",
            &["cold", "warming", "established", "paused"],
        )?,
    })
}

pub(super) fn resolve_rows(
    rows: &[MailPolicy],
    holder: Option<EntityId>,
    identity: Option<EntityId>,
) -> Option<MailPolicy> {
    let mut vault = rows.iter().filter(|row| row.scope == Scope::Vault);
    let mut effective = vault.next()?.clone();
    for row in vault {
        effective.restrict(row);
    }
    for row in rows {
        let applies = match row.scope {
            Scope::Vault => false,
            Scope::Holder(id) => Some(id) == holder,
            Scope::Identity(id) => Some(id) == identity,
        };
        if applies {
            effective.restrict(row);
        }
    }
    Some(effective)
}

/// Engine-authored manifest row; the evaluator itself reads only resolved
/// rows and does not carry a second compiled threshold table.
pub(crate) fn default_row() -> Value {
    Value::Map(vec![
        (Value::from("scope"), Value::from("vault")),
        (Value::from("holder"), Value::Nil),
        (Value::from("identity"), Value::Nil),
        (
            Value::from("known_first_touch"),
            Value::Array(vec![
                Value::from("user_introduction"),
                Value::from("inbound_first"),
            ]),
        ),
        (Value::from("cold_posture"), Value::from("hold_to_proposal")),
        (
            Value::from("max_complaint_rate"),
            Value::F64(COMPLAINT_CONSTRAINED_THRESHOLD),
        ),
        (
            Value::from("max_bounce_rate"),
            Value::F64(BOUNCE_CONSTRAINED_THRESHOLD),
        ),
        (Value::from("max_spam_labels"), Value::from(0_u64)),
        (
            Value::from("allowed_attestation"),
            Value::Array(vec![Value::from("a"), Value::from("b")]),
        ),
        (
            Value::from("allowed_warmup"),
            Value::Array(vec![Value::from("established")]),
        ),
        (Value::from("precedence"), Value::from(PRECEDENCE)),
    ])
}
