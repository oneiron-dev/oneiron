//! Claim-class descriptor values, schema checks and MessagePack codec.

use std::sync::LazyLock;

use jsonschema::Keyword;
use jsonschema::paths::{LazyLocation, Location};
use rmpv::Value;
use serde_json::json;

use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::CLAIM_CLASS_DESCRIPTOR;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::Store;
use crate::write_envelope::communication::{ClaimClassDescriptorRow, claim_class_descriptors};
use crate::write_envelope::communication_record::{
    elided_string, encode_value, required_bool, required_string, validate_keys_with_optional,
    value_map,
};

const KEY_PREDICATE: &str = "predicate";
const KEY_WRITE_CLASS: &str = "write_class";
const KEY_ENFORCEMENT: &str = "enforcement";
const KEY_RESTRICTIVE: &str = "restrictive";
const KEY_PROJECTOR_ONLY: &str = "projector_only";
const KEY_SEMANTICS_HASH: &str = "semantics_hash";
const KEY_STAMP_SEMANTICS_HASH: &str = "stamp_semantics_hash";
const KEY_STAMP_APPROVAL: &str = "stamp_approval";
const KEY_VALIDATOR_KIND: &str = "validator_kind";
const KEY_SUBJECT_KIND: &str = "subject_kind";
const KEY_SCHEMA: &str = "schema";

/// Pinned MessagePack keys every CLAIM_CLASS_DESCRIPTOR body carries.
pub const CLAIM_CLASS_DESCRIPTOR_BODY_KEYS: [&str; 6] = [
    KEY_PREDICATE,
    KEY_WRITE_CLASS,
    KEY_ENFORCEMENT,
    KEY_RESTRICTIVE,
    KEY_PROJECTOR_ONLY,
    KEY_SEMANTICS_HASH,
];

/// Every key a body may elide: the stamp's two (both present, a stamped row,
/// or both elided), and the validation keys, elided when they hold their
/// defaults (`builtin`, any subject, no schema).
const OPTIONAL_KEYS: [&str; 5] = [
    KEY_STAMP_SEMANTICS_HASH,
    KEY_STAMP_APPROVAL,
    KEY_VALIDATOR_KIND,
    KEY_SUBJECT_KIND,
    KEY_SCHEMA,
];

/// Domain of the semantics hash. Changing it changes every hash, and so
/// unbinds every stamp.
const SEMANTICS_HASH_DOMAIN: &str = "oneiron comm claim-class descriptor semantics v1";

/// Operation kind the owner's approve-once binds for one descriptor put.
pub(crate) const DESCRIPTOR_PUT_OPERATION: &str = "comm.claim_class_descriptor.put";

/// The engine keyword bounding a string's UTF-8 length.
const KEYWORD_MAX_UTF8_BYTES: &str = "maxUtf8Bytes";

/// A CRM-pack token's first and last character: no ASCII capital, no control
/// character and no white space (what `trim` removes).
const TOKEN_END_CHAR: &str =
    r"[^A-Z\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]";

/// A CRM-pack token's inner character: no ASCII capital and no control
/// character.
const TOKEN_INNER_CHAR: &str = r"[^A-Z\u0000-\u001F\u007F-\u009F]";

/// A CRM-pack text field's bound, in UTF-8 bytes.
const TOKEN_MAX_UTF8_BYTES: u64 = 512;

/// One compiled `generic` claim class: the subject its claims may name, its
/// value schema, and that schema compiled once.
pub(crate) struct GenericClassSeed {
    /// The subject its claims may name.
    pub(crate) subject_kind: ClaimSubjectKind,
    /// The value schema.
    pub(crate) schema: serde_json::Value,
    /// `schema` compiled; `None` when it does not compile.
    validator: Option<jsonschema::Validator>,
}

impl GenericClassSeed {
    fn new(subject_kind: ClaimSubjectKind, schema: serde_json::Value) -> Self {
        let validator = compile_schema(&schema).ok();
        Self {
            subject_kind,
            schema,
            validator,
        }
    }

    /// Whether `value` meets the class's schema.
    ///
    /// # Errors
    /// The compiled schema does not compile: a build defect, refused rather
    /// than passed.
    pub(crate) fn admits_value(&self, value: &serde_json::Value) -> Result<bool> {
        self.validator
            .as_ref()
            .map(|validator| validator.is_valid(value))
            .ok_or(Error::InvariantViolation(
                "a compiled claim-class schema does not compile",
            ))
    }
}

/// `comm.do_not_contact`: an entity subject, and exactly the value the CRM
/// pack's codec admits. A map of a required `scope` and an optional
/// `channel`, each a token of at most 512 UTF-8 bytes in the codec's
/// normalized form: non-empty, no control character, no ASCII capital, and
/// no white space at either end.
static DO_NOT_CONTACT: LazyLock<GenericClassSeed> = LazyLock::new(|| {
    let token_pattern = format!("^{TOKEN_END_CHAR}(?:{TOKEN_INNER_CHAR}*{TOKEN_END_CHAR})?$");
    GenericClassSeed::new(
        ClaimSubjectKind::Entity,
        json!({
            "type": "object",
            "properties": {
                "channel": {"$ref": "#/$defs/token"},
                "scope": {"$ref": "#/$defs/token"}
            },
            "required": ["scope"],
            "additionalProperties": false,
            "$defs": {
                "token": {
                    "type": "string",
                    "minLength": 1,
                    KEYWORD_MAX_UTF8_BYTES: TOKEN_MAX_UTF8_BYTES,
                    "pattern": token_pattern
                }
            }
        }),
    )
});

/// The build's compiled `generic` class for `predicate`, when it has one.
/// Every other compiled class is `builtin`.
pub(crate) fn generic_class_seed(predicate: &str) -> Option<&'static GenericClassSeed> {
    match predicate {
        crate::write_envelope::cohort_claims::PREDICATE_COMM_DO_NOT_CONTACT => {
            Some(&*DO_NOT_CONTACT)
        }
        _ => None,
    }
}

/// Whether `value` meets `schema`, the schema of `predicate`'s class: through
/// the compiled class's validator when `schema` is its schema, else compiled
/// here.
pub(crate) fn value_meets_schema(
    predicate: &str,
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<bool> {
    match generic_class_seed(predicate) {
        Some(seed) if seed.schema == *schema => seed.admits_value(value),
        _ => Ok(compile_schema(schema)?.is_valid(value)),
    }
}

/// Checks `schema`, the schema of `predicate`'s class, compiles: known
/// without compiling it again when it is the compiled class's schema.
pub(crate) fn check_schema_compiles(predicate: &str, schema: &serde_json::Value) -> Result<()> {
    match generic_class_seed(predicate) {
        Some(seed) if seed.schema == *schema && seed.validator.is_some() => Ok(()),
        _ => compile_schema(schema).map(drop),
    }
}

/// ARCH-0057 §4 write class of a claim class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimWriteClass {
    /// Written only from recorded evidence (a projector's own records).
    Recorded,
    /// Written only on a human ruling.
    HumanRuled,
    /// Written by ordinary claim doors.
    Ordinary,
}

impl ClaimWriteClass {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::HumanRuled => "human_ruled",
            Self::Ordinary => "ordinary",
        }
    }

    /// Parses the pinned wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "recorded" => Some(Self::Recorded),
            "human_ruled" => Some(Self::HumanRuled),
            "ordinary" => Some(Self::Ordinary),
            _ => None,
        }
    }
}

/// How a claim class's claims are checked (ARCH-0057 `validator_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimValidatorKind {
    /// The descriptor's schema checks the value.
    Generic,
    /// The build's own family validator checks the claim: the escape hatch
    /// for classes a schema cannot express.
    Builtin,
}

impl ClaimValidatorKind {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Builtin => "builtin",
        }
    }

    /// Parses the pinned wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "generic" => Some(Self::Generic),
            "builtin" => Some(Self::Builtin),
            _ => None,
        }
    }
}

/// The subject a claim class's claims may name (ARCH-0057 `subject_kind`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimSubjectKind {
    /// Any subject.
    Any,
    /// An entity, of any type.
    Entity,
    /// An entity of one registered type, named by its registry kind
    /// (`PERSON`).
    EntityType(String),
    /// An edge.
    Edge,
}

impl ClaimSubjectKind {
    /// Wire spelling: `any`, `entity`, `entity:<KIND>` or `edge`.
    #[must_use]
    pub fn to_wire(&self) -> String {
        match self {
            Self::Any => "any".to_owned(),
            Self::Entity => "entity".to_owned(),
            Self::EntityType(kind) => format!("entity:{kind}"),
            Self::Edge => "edge".to_owned(),
        }
    }

    /// Parses the wire spelling; an entity type must name a registered kind.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "any" => Some(Self::Any),
            "entity" => Some(Self::Entity),
            "edge" => Some(Self::Edge),
            _ => {
                let kind = value.strip_prefix("entity:")?;
                crate::registry::ENTITY_TYPE_REGISTRY
                    .iter()
                    .any(|entry| entry.kind == kind)
                    .then(|| Self::EntityType(kind.to_owned()))
            }
        }
    }

    /// Whether a claim of this class may name `subject`, read without a
    /// store: an entity is admitted for a set type whatever type it is.
    pub(crate) fn admits_without_store(
        &self,
        subject: &crate::write_envelope::claim_body::ClaimSubject,
    ) -> bool {
        use crate::write_envelope::claim_body::ClaimSubject;
        matches!(
            (self, subject),
            (Self::Any, _)
                | (Self::Entity | Self::EntityType(_), ClaimSubject::Entity(_))
                | (Self::Edge, ClaimSubject::Edge { .. })
        )
    }

    /// Whether a claim of this class may name `subject`. An entity of a set
    /// type that is not in the store yet (sync can carry a claim before its
    /// subject) is admitted; one stored as another type is not.
    pub(crate) fn admits(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        subject: &crate::write_envelope::claim_body::ClaimSubject,
    ) -> Result<bool> {
        use crate::write_envelope::claim_body::ClaimSubject;
        Ok(match (self, subject) {
            (Self::Any, _)
            | (Self::Entity, ClaimSubject::Entity(_))
            | (Self::Edge, ClaimSubject::Edge { .. }) => true,
            (Self::EntityType(kind), ClaimSubject::Entity(id)) => {
                store.port_entity_record(txn, id)?.is_none_or(|record| {
                    crate::registry::entity_type_registry_entry(record.entity_type)
                        .is_some_and(|entry| entry.kind == kind)
                })
            }
            _ => false,
        })
    }
}

/// The human stamp that lets a descriptor's `enforcement=true` count: the
/// semantics hash it was minted over, and the owner approve-once digest that
/// minted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementStamp {
    /// The semantics hash the owner stamped.
    pub semantics_hash: [u8; 32],
    /// The owner approve-once effect digest that minted this stamp.
    pub approval: [u8; 32],
}

/// One claim class, as the synced descriptor entity describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimClassDescriptor {
    /// The predicate this class describes.
    pub predicate: String,
    /// Who may write a head of this class.
    pub write_class: ClaimWriteClass,
    /// Whether the gate may consult this class's claim state. Counts only
    /// when stamped ([`Self::enforced`]).
    pub enforcement: bool,
    /// Whether a head of this class can only add suppression.
    pub restrictive: bool,
    /// Whether only a projector authors this class.
    pub projector_only: bool,
    /// The owner's stamp over the semantics hash, when one was minted.
    pub enforcement_stamp: Option<EnforcementStamp>,
    /// Whether the schema or the build's family validator checks the class.
    pub validator_kind: ClaimValidatorKind,
    /// The subject its claims may name.
    pub subject_kind: ClaimSubjectKind,
    /// A `generic` class's structural value schema: JSON Schema (Draft
    /// 2020-12) over the claim value read as JSON. A `builtin` class has none.
    pub schema: Option<serde_json::Value>,
}

impl ClaimClassDescriptor {
    /// The compiled row as an unstamped descriptor. A class the build
    /// compiles as `generic` carries that class's subject kind and schema;
    /// every other seed is `builtin`, of any subject, with no schema, and its
    /// family validator checks it.
    #[must_use]
    pub fn from_compiled(row: &ClaimClassDescriptorRow) -> Self {
        let generic = generic_class_seed(row.predicate);
        Self {
            predicate: row.predicate.to_owned(),
            write_class: ClaimWriteClass::parse(row.write_class)
                .unwrap_or(ClaimWriteClass::Ordinary),
            enforcement: row.enforcement,
            restrictive: row.restrictive,
            projector_only: row.projector_only,
            enforcement_stamp: None,
            validator_kind: if generic.is_some() {
                ClaimValidatorKind::Generic
            } else {
                ClaimValidatorKind::Builtin
            },
            subject_kind: generic.map_or(ClaimSubjectKind::Any, |seed| seed.subject_kind.clone()),
            schema: generic.map(|seed| seed.schema.clone()),
        }
    }

    /// Whether the descriptor checks its claims beyond the family validator:
    /// a subject kind or a schema.
    #[must_use]
    pub fn declares_validation(&self) -> bool {
        self.validator_kind == ClaimValidatorKind::Generic
            || self.subject_kind != ClaimSubjectKind::Any
    }

    /// The hash a stamp binds: predicate, write class, `restrictive` and
    /// `projector_only`, and the validator kind, subject kind and schema when
    /// the descriptor declares them. `enforcement` is what a stamp approves,
    /// so it is not part of what the stamp binds; changing any bound field
    /// needs a new stamp.
    #[must_use]
    pub fn semantics_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SEMANTICS_HASH_DOMAIN);
        for field in [
            self.predicate.as_bytes(),
            self.write_class.as_str().as_bytes(),
        ] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        hasher.update(&[u8::from(self.restrictive), u8::from(self.projector_only)]);
        // A descriptor that declares no validation hashes without the
        // validation fields, so a `builtin` seed's hash is its four fields'.
        if self.declares_validation() {
            let schema = self.schema.as_ref().map(schema_text).unwrap_or_default();
            for field in [
                self.validator_kind.as_str().as_bytes(),
                self.subject_kind.to_wire().as_bytes(),
                schema.as_bytes(),
            ] {
                hasher.update(&(field.len() as u64).to_le_bytes());
                hasher.update(field);
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// Whether `enforcement=true` counts here: an owner stamp over exactly
    /// this semantics hash, or the compiled row for this predicate enforcing
    /// the same semantics (an identical rebuild carries the build's stamp).
    /// A stamp over other semantics reads as not enforced.
    #[must_use]
    pub fn enforced(&self) -> bool {
        if !self.enforcement {
            return false;
        }
        let semantics = self.semantics_hash();
        self.enforcement_stamp
            .is_some_and(|stamp| stamp.semantics_hash == semantics)
            || compiled_row(&self.predicate).is_some_and(|row| {
                row.enforcement && Self::from_compiled(&row).semantics_hash() == semantics
            })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        crate::write_envelope::claim_predicate::validate_predicate(&self.predicate, false)?;
        match (self.validator_kind, &self.schema) {
            (ClaimValidatorKind::Generic, Some(schema)) => {
                check_schema_compiles(&self.predicate, schema)
            }
            (ClaimValidatorKind::Generic, None) => {
                Err(invalid("a generic claim class declares its schema"))
            }
            (ClaimValidatorKind::Builtin, None) => Ok(()),
            (ClaimValidatorKind::Builtin, Some(_)) => Err(invalid(
                "a builtin claim class has no schema; its family validator checks it",
            )),
        }
    }
}

/// A schema as the body and the semantics hash carry it.
fn schema_text(schema: &serde_json::Value) -> String {
    schema.to_string()
}

/// The schema compiled: Draft 2020-12 whatever it declares, with the
/// engine's `maxUtf8Bytes` keyword, local references only (the engine is
/// built without remote resolution).
pub(crate) fn compile_schema(schema: &serde_json::Value) -> Result<jsonschema::Validator> {
    jsonschema::draft202012::options()
        .with_keyword(KEYWORD_MAX_UTF8_BYTES, max_utf8_bytes_keyword)
        .build(schema)
        .map_err(|_| Error::InvalidClaimBody("a claim class's schema is not a valid JSON Schema"))
}

/// `maxUtf8Bytes` compiled: its bound is a non-negative integer.
fn max_utf8_bytes_keyword<'a>(
    _: &'a serde_json::Map<String, serde_json::Value>,
    bound: &'a serde_json::Value,
    path: Location,
) -> std::result::Result<Box<dyn Keyword>, jsonschema::ValidationError<'a>> {
    let Some(max) = bound.as_u64() else {
        return Err(jsonschema::ValidationError::custom(
            path,
            Location::new(),
            bound,
            "maxUtf8Bytes is a non-negative integer",
        ));
    };
    Ok(Box::new(MaxUtf8Bytes(max)))
}

/// A string's UTF-8 length is at most the bound; any other value passes.
struct MaxUtf8Bytes(u64);

impl Keyword for MaxUtf8Bytes {
    fn validate<'i>(
        &self,
        instance: &'i serde_json::Value,
        location: &LazyLocation<'_, '_>,
    ) -> std::result::Result<(), jsonschema::ValidationError<'i>> {
        if self.is_valid(instance) {
            return Ok(());
        }
        Err(jsonschema::ValidationError::custom(
            Location::new(),
            location.into(),
            instance,
            "string is longer than maxUtf8Bytes",
        ))
    }

    fn is_valid(&self, instance: &serde_json::Value) -> bool {
        instance
            .as_str()
            .is_none_or(|text| u64::try_from(text.len()).is_ok_and(|len| len <= self.0))
    }
}

/// A claim value as JSON, for a schema to check. `None` for what JSON cannot
/// hold as it is: bytes, extension types, a map key that is not a string or
/// is repeated, a non-UTF-8 string and a number that is not finite.
pub(crate) fn json_value(value: &Value) -> Option<serde_json::Value> {
    Some(match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Integer(number) => match number.as_u64() {
            Some(unsigned) => unsigned.into(),
            None => number.as_i64()?.into(),
        },
        Value::F32(number) => serde_json::Number::from_f64(f64::from(*number))?.into(),
        Value::F64(number) => serde_json::Number::from_f64(*number)?.into(),
        Value::String(text) => text.as_str()?.into(),
        Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(json_value).collect::<Option<Vec<_>>>()?)
        }
        Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, item) in entries {
                if map
                    .insert(key.as_str()?.to_owned(), json_value(item)?)
                    .is_some()
                {
                    return None;
                }
            }
            serde_json::Value::Object(map)
        }
        Value::Binary(_) | Value::Ext(..) => return None,
    })
}

pub(crate) fn compiled_row(predicate: &str) -> Option<ClaimClassDescriptorRow> {
    claim_class_descriptors()
        .into_iter()
        .find(|row| row.predicate == predicate)
}

/// The compiled `comm.*` row for `predicate` as a descriptor.
pub(crate) fn compiled_descriptor(predicate: &str) -> Option<ClaimClassDescriptor> {
    compiled_row(predicate).map(|row| ClaimClassDescriptor::from_compiled(&row))
}

/// The one descriptor entity id for `predicate`, the same on every node.
pub fn claim_class_descriptor_id(predicate: &str) -> Result<EntityId> {
    EntityId::derive(CLAIM_CLASS_DESCRIPTOR, &[predicate.as_bytes()])
}

pub(crate) fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(crate) fn hash_hex(bytes: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*bytes).to_hex().to_string()
}

fn hash_from_hex(value: &str) -> Result<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .map(|hash| *hash.as_bytes())
        .map_err(|_| invalid("claim-class descriptor hash is not 32-byte hex"))
}

/// Encodes a CLAIM_CLASS_DESCRIPTOR body in canonical key order.
pub fn encode_claim_class_descriptor(descriptor: &ClaimClassDescriptor) -> Result<Vec<u8>> {
    descriptor.validate()?;
    let mut entries = vec![
        (
            Value::from(KEY_PREDICATE),
            Value::from(descriptor.predicate.as_str()),
        ),
        (
            Value::from(KEY_WRITE_CLASS),
            Value::from(descriptor.write_class.as_str()),
        ),
        (
            Value::from(KEY_ENFORCEMENT),
            Value::from(descriptor.enforcement),
        ),
        (
            Value::from(KEY_RESTRICTIVE),
            Value::from(descriptor.restrictive),
        ),
        (
            Value::from(KEY_PROJECTOR_ONLY),
            Value::from(descriptor.projector_only),
        ),
        (
            Value::from(KEY_SEMANTICS_HASH),
            Value::from(hash_hex(&descriptor.semantics_hash())),
        ),
    ];
    if let Some(stamp) = descriptor.enforcement_stamp {
        entries.push((
            Value::from(KEY_STAMP_SEMANTICS_HASH),
            Value::from(hash_hex(&stamp.semantics_hash)),
        ));
        entries.push((
            Value::from(KEY_STAMP_APPROVAL),
            Value::from(hash_hex(&stamp.approval)),
        ));
    }
    if descriptor.validator_kind != ClaimValidatorKind::Builtin {
        entries.push((
            Value::from(KEY_VALIDATOR_KIND),
            Value::from(descriptor.validator_kind.as_str()),
        ));
    }
    if descriptor.subject_kind != ClaimSubjectKind::Any {
        entries.push((
            Value::from(KEY_SUBJECT_KIND),
            Value::from(descriptor.subject_kind.to_wire()),
        ));
    }
    if let Some(schema) = &descriptor.schema {
        entries.push((Value::from(KEY_SCHEMA), Value::from(schema_text(schema))));
    }
    encode_value(&Value::Map(entries))
}

/// Decodes a CLAIM_CLASS_DESCRIPTOR body: exact keys, a known write class, a
/// valid predicate, a stored semantics hash that matches its fields, and the
/// stamp's two keys together or not at all.
pub fn decode_claim_class_descriptor(bytes: &[u8]) -> Result<ClaimClassDescriptor> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .map_err(|_| invalid("claim-class descriptor body is not valid MessagePack"))?;
    let entries = value_map(&value)?;
    validate_keys_with_optional(entries, &CLAIM_CLASS_DESCRIPTOR_BODY_KEYS, &OPTIONAL_KEYS)?;
    let stamp = match (
        elided_string(entries, KEY_STAMP_SEMANTICS_HASH)?,
        elided_string(entries, KEY_STAMP_APPROVAL)?,
    ) {
        (Some(semantics_hash), Some(approval)) => Some(EnforcementStamp {
            semantics_hash: hash_from_hex(semantics_hash)?,
            approval: hash_from_hex(approval)?,
        }),
        (None, None) => None,
        _ => return Err(invalid("claim-class descriptor stamp is half present")),
    };
    let descriptor = ClaimClassDescriptor {
        predicate: required_string(entries, KEY_PREDICATE)?.to_owned(),
        write_class: ClaimWriteClass::parse(required_string(entries, KEY_WRITE_CLASS)?)
            .ok_or_else(|| invalid("claim-class descriptor write class is unknown"))?,
        enforcement: required_bool(entries, KEY_ENFORCEMENT)?,
        restrictive: required_bool(entries, KEY_RESTRICTIVE)?,
        projector_only: required_bool(entries, KEY_PROJECTOR_ONLY)?,
        enforcement_stamp: stamp,
        validator_kind: elided_string(entries, KEY_VALIDATOR_KIND)?
            .map_or(Some(ClaimValidatorKind::Builtin), ClaimValidatorKind::parse)
            .ok_or_else(|| invalid("claim-class descriptor validator kind is unknown"))?,
        subject_kind: elided_string(entries, KEY_SUBJECT_KIND)?
            .map_or(Some(ClaimSubjectKind::Any), ClaimSubjectKind::parse)
            .ok_or_else(|| invalid("claim-class descriptor subject kind is unknown"))?,
        schema: elided_string(entries, KEY_SCHEMA)?
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| invalid("claim-class descriptor schema is not JSON"))?,
    };
    descriptor.validate()?;
    if hash_from_hex(required_string(entries, KEY_SEMANTICS_HASH)?)? != descriptor.semantics_hash()
    {
        return Err(invalid(
            "claim-class descriptor semantics hash does not match its fields",
        ));
    }
    Ok(descriptor)
}
