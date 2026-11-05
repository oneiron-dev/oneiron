//! The pairing/link/redeem/slip-revoke routes in the OpenAPI document (FIX 3936).
//!
//! The five routes are wired in `routes.rs:216-220` but absent from the OpenAPI
//! declarations: `GET /.well-known/oneiron` (`pairing::descriptor`),
//! `POST /v1/core/pairing/links` (`pairing::create_link`),
//! `POST /v1/core/pairing/redeem` (`pairing::redeem`),
//! `POST /v1/core/pairing/oauth` (`pairing::oauth_exchange`) and
//! `POST /v1/core/slips/revoke` (`pairing::revoke`). This leaf adds their
//! operations; no other route is touched and no working route changes.
//!
//! Pattern: `voice_bank_paths.rs` (one struct table plus an `operation`
//! builder plus a `merge_*_paths` that inserts each row). Voice bank serves
//! uniform owner-bearer `/v1/ai` rows, so this leaf carries two small
//! per-route extensions for pairing's mixed surface: an explicit
//! `operation` id (mixed `/.well-known` and `/v1/core` prefixes) and
//! per-route auth (`owner_bearer` for the two owner-act rows, `auth_header`
//! for the OAuth JWT header). Schemas, security and statuses are otherwise
//! composed exactly as voice bank composes them.
//!
//! Binding: manual JSON transcribed field by field from the actual request
//! and response types in `api/pairing.rs` and the engine types they name
//! (`Scope`, `PairingPrincipal`, `PairingLink`, `CommReach`,
//! `MachineOwnership`, `MachineEnrolment`, `AuthorityCheckpointPin`). Each
//! schema cites its source lines. No `ToSchema`/`JsonSchema` derive was
//! added, no handler, auth, ceiling, key, revoke or pairing body was
//! edited, and no engine type was touched, so every runtime body,
//! serialization shape and gate is byte unchanged. Requests with
//! `deny_unknown_fields` set `additionalProperties: false`; responses omit
//! it, as the manual leaves do.
//!
//! Auth and statuses are the handlers' own: `create_link` and `revoke`
//! require an owner-act credential (`check_request_owner_act`,
//! `CoreBearer`); `descriptor` and `redeem` take no bearer; `oauth_exchange`
//! takes an OAuth relay JWT as `Authorization: Bearer` (never a slip).
//! Success is always 200. Refusals are only the handlers' own 400 (a scope
//! the vault refuses on link mint), 401 (no or failed credential, proof or
//! code) and 403 (narrower than owner-act or no live owner); there is no
//! idempotency 409 (these rows carry no idempotency layer), no 500 and no
//! new refusal, hold, default, cap or compat.
//!
//! Proof limits: source reading only. No cargo, rustc, build, test, server
//! or probe ran on this host. The `openapi.json` document is assembled at
//! runtime, so no generated artifact is committed here; `oneiron.skills.md`
//! and `agent-verbs` are untouched (no new facade verb).

use serde_json::{Map, Value, json};

/// One pairing/slip route: its method, path, operation id, what it does, its
/// body's schema (none for the descriptor read), its answer's schema, each
/// refusal it answers, and its auth (owner bearer and/or OAuth header).
struct PairingRoute {
    method: &'static str,
    path: &'static str,
    operation: &'static str,
    summary: &'static str,
    body: Option<fn() -> Value>,
    answer: fn() -> Value,
    refusals: &'static [(&'static str, &'static str)],
    /// True for the two owner-act rows (`create_link`, `revoke`): the
    /// operation names `CoreBearer`. False names `security: []`.
    owner_bearer: bool,
    /// True only for the OAuth row: the operation lists the `Authorization`
    /// header carrying the relay JWT (never a slip).
    auth_header: bool,
}

const PAIRING_ROUTES: &[PairingRoute] = &[
    PairingRoute {
        method: "get",
        path: "/.well-known/oneiron",
        operation: "pairing_descriptor",
        summary: "Public pairing liveness (pairing::descriptor, routes.rs:216): the protocol, slip version, binding and redeem endpoint. No credential; always 200.",
        body: None,
        answer: descriptor_answer,
        refusals: &[],
        owner_bearer: false,
        auth_header: false,
    },
    PairingRoute {
        method: "post",
        path: "/v1/core/pairing/links",
        operation: "pairing_create_link",
        summary: "Mints a pairing link (pairing::create_link, routes.rs:217) on an owner-act credential: the scope, slip lifetime and principal, or a machine link when machine names the owner's answer (yours, work_school or rented).",
        body: Some(create_link_body),
        answer: pairing_link_answer,
        refusals: &[
            (
                "400",
                "The scope the vault refuses (InvalidPairingScope on scope.facets, pairing.rs with_issuer).",
            ),
            (
                "401",
                "No owner-grade credential, the vault holds no issuer, or the link was not issued (check_request_owner_act or with_issuer refused).",
            ),
            (
                "403",
                "The credential is narrower than owner-act, names no live owner, or the host root acts as nobody (owner-act or owner proof refused).",
            ),
        ],
        owner_bearer: true,
        auth_header: false,
    },
    PairingRoute {
        method: "post",
        path: "/v1/core/pairing/redeem",
        operation: "pairing_redeem",
        summary: "Redeems a pairing link (pairing::redeem, routes.rs:218) with no bearer: the code, holder, binding key and signature, plus the machine enrolment for a machine link and the possession proof for a re-pair. Answers the slip token, pin, home and reach.",
        body: Some(redeem_body),
        answer: paired_answer,
        refusals: &[(
            "401",
            "No such holder, or the code, binding key, signature, machine enrolment or possession proof does not verify (every redeem check refuses unauthenticated).",
        )],
        owner_bearer: false,
        auth_header: false,
    },
    PairingRoute {
        method: "post",
        path: "/v1/core/pairing/oauth",
        operation: "pairing_oauth_exchange",
        summary: "Exchanges an OAuth relay identity for a scoped slip (pairing::oauth_exchange, routes.rs:219): Authorization Bearer carries the relay JWT (never a v2.slip.* token) and the body carries the binding key, nonce, signature and optional lifetime narrowing.",
        body: Some(oauth_body),
        answer: paired_answer,
        refusals: &[(
            "401",
            "No Bearer JWT, the relay identity does not verify, the subject is unknown, the binding proof does not verify, or the JWT or issuer is missing or expired (every oauth check refuses unauthenticated).",
        )],
        owner_bearer: false,
        auth_header: true,
    },
    PairingRoute {
        method: "post",
        path: "/v1/core/slips/revoke",
        operation: "slips_revoke",
        summary: "Revokes one capability slip (pairing::revoke, routes.rs:220) on an owner-act credential: the slip id as 32 numbers. Answers revoked true.",
        body: Some(revoke_body),
        answer: revoked_answer,
        refusals: &[
            (
                "401",
                "No owner-grade credential, the vault holds no issuer, or the slip was not revoked (check_request_owner_act or with_issuer refused).",
            ),
            (
                "403",
                "The credential is narrower than owner-act, names no live owner, or the host root acts as nobody (owner-act refused).",
            ),
        ],
        owner_bearer: true,
        auth_header: false,
    },
];

/// The `/v1` refusal envelope: pairing handlers return
/// `Result<_, EnvelopedApiError>`, which serializes the `ApiError` as an
/// `ApiErrorEnvelope` at the same status.
fn refusal_schema() -> Value {
    json!({"$ref": "#/components/schemas/ApiErrorEnvelope"})
}

/// Adds each pairing/slip route's operation to `spec`'s paths.
pub(super) fn merge_pairing_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for route in PAIRING_ROUTES {
        let Some(item) = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
        else {
            continue;
        };
        item.insert(route.method.to_owned(), operation(route));
    }
}

fn operation(route: &PairingRoute) -> Value {
    let mut operation = Map::new();
    operation.insert("tags".to_owned(), json!(["pairing"]));
    operation.insert("summary".to_owned(), json!(route.summary));
    operation.insert("operationId".to_owned(), json!(route.operation));
    if route.owner_bearer {
        operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
    } else {
        operation.insert("security".to_owned(), json!([]));
    }
    let mut parameters: Vec<Value> = route
        .path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}))
        .collect();
    if route.auth_header {
        parameters.push(json!({"name": "Authorization", "in": "header", "required": true, "schema": {"type": "string"}, "description": "The OAuth relay JWT as Bearer (never a v2.slip.* token); the vault verifies it against its issuer, audience and keys."}));
    }
    operation.insert("parameters".to_owned(), Value::Array(parameters));
    if let Some(body) = route.body {
        operation.insert(
            "requestBody".to_owned(),
            json!({"required": true, "content": {"application/json": {"schema": body()}}}),
        );
    }
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": "The route's typed answer.",
            "content": {"application/json": {"schema": (route.answer)()}}
        }),
    );
    for (status, description) in route.refusals {
        responses.insert(
            (*status).to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": refusal_schema()}}
            }),
        );
    }
    operation.insert("responses".to_owned(), Value::Object(responses));
    Value::Object(operation)
}

/// The descriptor answer: `PairingDescriptor`
/// (`oneiron/src/authority/slip_pairing/mod.rs:28-32`, four required
/// fields). The handler answers `PairingDescriptor::default()`
/// (`pairing.rs:16-18`): protocol `oneiron-pairing`, slip version 2,
/// binding `ed25519`, endpoint `/v1/core/pairing/redeem` (mod.rs:34-42).
fn descriptor_answer() -> Value {
    json!({
        "type": "object",
        "required": ["protocol", "slip_version", "binding", "pairing_endpoint"],
        "properties": {
            "protocol": {"type": "string", "description": "Always oneiron-pairing."},
            "slip_version": {"type": "integer", "description": "Always 2."},
            "binding": {"type": "string", "description": "Always ed25519."},
            "pairing_endpoint": {"type": "string", "description": "Always /v1/core/pairing/redeem."}
        }
    })
}

/// One powerset scope axis: `ScopeAxis<T>` (`scope.rs:30-34`), tagged
/// `kind` with `values` (`scope.rs:27-29`, snake case). Bottom and all carry
/// no values; some carries the set. An empty some decodes to bottom, never
/// to all (`scope.rs:53`). The wire table denies unknown fields
/// (`scope.rs:39-43`).
fn scope_axis_schema(items: Value) -> Value {
    json!({
        "oneOf": [
            {"type": "object", "required": ["kind"], "additionalProperties": false, "properties": {"kind": {"const": "bottom"}}},
            {"type": "object", "required": ["kind"], "additionalProperties": false, "properties": {"kind": {"const": "all"}}},
            {"type": "object", "required": ["kind", "values"], "additionalProperties": false, "properties": {"kind": {"const": "some"}, "values": {"type": "array", "items": items}}}
        ]
    })
}

/// The sensitivity ceiling: `SensitivityCeiling` (`scope.rs:185-188`,
/// bottom or at most a band). Its wire (`scope.rs:198-202`) spells bottom,
/// all (accepted on read as the top ceiling, `scope.rs:207-208`) and at most
/// with `value` (singular). Bands are `Sensitivity` (`scope.rs:153-162`,
/// snake case).
fn sensitivity_ceiling_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "object", "required": ["kind"], "additionalProperties": false, "properties": {"kind": {"const": "bottom"}}},
            {"type": "object", "required": ["kind"], "additionalProperties": false, "properties": {"kind": {"const": "all"}}},
            {"type": "object", "required": ["kind", "value"], "additionalProperties": false, "properties": {"kind": {"const": "at_most"}, "value": {"type": "string", "enum": ["public", "private", "sensitive", "restricted"]}}}
        ]
    })
}

/// The link scope: `Scope` (`scope.rs:260-266`, six axes) with struct-wide
/// defaults and denied unknown fields (`scope.rs:259`). A missing axis
/// defaults to bottom (`Scope::default`, `ScopeAxis::Bottom` default
/// `scope.rs:32`), so none is required.
fn scope_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "worlds": scope_axis_schema(json!({"type": "string", "description": "A world id as canonical lower hex (ScopeId serializes as hex, scope.rs:8-21)."})),
            "facets": scope_axis_schema(json!({"type": "string", "description": "A facet id as canonical lower hex."})),
            "bands": scope_axis_schema(json!({"type": "integer", "minimum": 0, "maximum": 255, "description": "A kind band byte."})),
            "audience": scope_axis_schema(json!({"type": "string", "description": "A project id as canonical lower hex."})),
            "verbs": scope_axis_schema(json!({"type": "string", "description": "A verb class name, not a tool name."})),
            "sensitivity": sensitivity_ceiling_schema()
        }
    })
}

/// Whom the paired slip may message: `CommReach` (`comm_reach.rs:25-33`,
/// snake case `comm_reach.rs:24`). Absent on a link means the vault-wide
/// reach (`effective_slip_comm`, `comm_reach.rs:66-70`).
fn comm_reach_schema() -> Value {
    json!({"type": "string", "enum": ["parent", "subtree", "project", "vault"]})
}

/// The link principal: `PairingPrincipal` (`slip_pairing/mod.rs:97-111`,
/// five optional fields, denied unknown fields `mod.rs:96`). All are
/// optional; `write_facet` and `comm` carry explicit defaults
/// (`mod.rs:105,110`).
fn principal_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "holder_ref": {"type": "string", "description": "The holder the link is pinned to, when pinned."},
            "actor_class": {"type": "string", "description": "The actor class the link admits (human, agent or system)."},
            "org_ref": {"type": "string", "description": "The organization the link is pinned to, when pinned."},
            "write_facet": {"type": "string", "description": "The facet id (hex) writes are born in when the scope reads several; the smallest when unnamed (mod.rs:101-106)."},
            "comm": comm_reach_schema()
        }
    })
}

/// The link-mint body: `CreateLink` (`pairing.rs:21-29`, denied unknown
/// fields `pairing.rs:20`). Scope and lifetime are required; principal
/// defaults (`pairing.rs:24`) and machine is optional (`pairing.rs:28`).
/// Machine answers are `MachineOwnership` (`machine_profile.rs:70-73`,
/// snake case): only `yours` makes the machine one of the owner's
/// (`pairing.rs:26-29`).
fn create_link_body() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["scope", "lifetime_secs"],
        "properties": {
            "scope": scope_schema(),
            "lifetime_secs": {"type": "integer", "minimum": 0, "description": "How long the paired slip lives, in seconds."},
            "principal": principal_schema(),
            "machine": {"type": "string", "enum": ["yours", "work_school", "rented"], "description": "The owner's answer for a machine this link adds; only yours makes it one of the owner's."}
        }
    })
}

/// The minted link: `PairingLink` (`slip_pairing/mod.rs:47-57`). Code and
/// expiry are required; the pin ref rides only when the vault holds an
/// attested checkpoint (`mod.rs:50-54`, skipped when none); comm is
/// required (`vault` when the owner named none, `mod.rs:55-57`).
fn pairing_link_answer() -> Value {
    json!({
        "type": "object",
        "required": ["code", "expires_at", "comm"],
        "properties": {
            "code": {"type": "string", "description": "The single-use link code (8 Crockford base32 chars, mod.rs:148-151)."},
            "expires_at": {"type": "integer", "minimum": 0, "description": "When the link expires, as Unix seconds."},
            "pin": pairing_pin_ref_schema(),
            "comm": comm_reach_schema()
        }
    })
}

/// What a delivered link says of its pin: `PairingPinRef`
/// (`slip_pairing/mod.rs:63-65`): the challenge and the pin digest, each 32
/// bytes as 32 numbers.
fn pairing_pin_ref_schema() -> Value {
    json!({
        "type": "object",
        "required": ["challenge", "digest"],
        "properties": {
            "challenge": byte_array_32_schema("The link's fresh single-use challenge, 32 bytes as 32 numbers."),
            "digest": byte_array_32_schema("The pin digest the joining device checks the redeemed pin against, 32 bytes as 32 numbers.")
        }
    })
}

/// Thirty-two bytes as a JSON array of thirty-two numbers (`[u8; 32]`
/// serde shape, used for slip ids, pin hashes and checkpoint hashes).
fn byte_array_32_schema(description: &str) -> Value {
    json!({
        "type": "array",
        "minItems": 32,
        "maxItems": 32,
        "items": {"type": "integer", "minimum": 0, "maximum": 255},
        "description": description
    })
}

/// The redeem body: `RedeemLink` (`pairing.rs:180-194`, denied unknown
/// fields `pairing.rs:179`). Code, holder, binding key and signature are
/// required; machine and possession are optional (`pairing.rs:187,193`).
/// The binding key is 64 hex (`parse_slip_id`, `pairing.rs:289`); the
/// signature and possession proof are 128 hex (`parse_signature`,
/// `pairing.rs:290,297`).
fn redeem_body() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["code", "holder_ref", "binding_key", "signature"],
        "properties": {
            "code": {"type": "string", "description": "The link code the owner delivered."},
            "holder_ref": {"type": "string", "description": "The joining holder as an entity id in hex; it must already exist (pairing.rs:279-288)."},
            "binding_key": {"type": "string", "description": "The joining holder's fresh signing key id, 64 lower hex."},
            "signature": {"type": "string", "description": "The binding signature over the redemption, 128 lower hex."},
            "machine": machine_enrolment_schema(),
            "machine_possession": {"type": "string", "description": "The install-key signature over the redemption (machine_possession_transcript), 128 lower hex; read only beside machine, re-pairs an already held machine credential only (pairing.rs:189-194)."}
        }
    })
}

/// The joining machine's enrolment on the wire: `MachineEnrolment`
/// (`pairing.rs:200-209`, seven required fields, denied unknown fields
/// `pairing.rs:199`). Vault and machine-key ids are 64 hex, the machine is
/// an entity id in hex, the device class is required, the encryption key is
/// base64 and the proof is 128 hex (`MachineEnrolment::request`,
/// `pairing.rs:214-232`).
fn machine_enrolment_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["vault_id", "machine", "machine_key", "device_class", "encryption_suite", "encryption_key", "machine_proof"],
        "properties": {
            "vault_id": {"type": "string", "description": "The vault id, 64 lower hex."},
            "machine": {"type": "string", "description": "The joining machine as an entity id in hex."},
            "machine_key": {"type": "string", "description": "The joining machine's key id, 64 lower hex."},
            "device_class": {"type": "string", "enum": ["phone", "computer"], "description": "What kind of machine it is, as its host declares it (MachineDeviceClass, machine_profile.rs:94-97)."},
            "encryption_suite": {"type": "integer", "minimum": 0, "maximum": 65535, "description": "The encryption suite number."},
            "encryption_key": {"type": "string", "description": "The machine's public encryption key in standard base64."},
            "machine_proof": {"type": "string", "description": "The enrolment proof, 128 lower hex."}
        }
    })
}

/// The paired answer: `Paired` (`pairing.rs:235-251`, serialize only).
/// Token and comm are always present; pin and home ride only when present
/// (skipped when none, `pairing.rs:239,243`); re-paired rides only when
/// true (skipped when false, `pairing.rs:247`). Redeem fills pin, home and
/// re-paired from the redemption (`pairing.rs:344-347`); the OAuth door
/// answers none, no home and not re-paired (`pairing.rs:171-173`).
fn paired_answer() -> Value {
    json!({
        "type": "object",
        "required": ["token", "comm"],
        "properties": {
            "token": {"type": "string", "description": "The paired capability slip token (v2.slip.*)."},
            "pin": checkpoint_pin_schema(),
            "home": paired_home_schema(),
            "re_paired": {"type": "boolean", "description": "True when the link re-paired an already held machine credential only; omitted otherwise."},
            "comm": comm_reach_schema()
        }
    })
}

/// What a new device trusts a checkpoint by: `AuthorityCheckpointPin`
/// (`checkpoint_attest.rs:307-318`, six required fields). The four hashes
/// are 32 bytes as 32 numbers; the policy is the eligible roots and quorum
/// and the bindings are one key certificate per root, ascending by root.
/// Policy and binding internals (authority keys, signed statements) are
/// objects here with their sources cited, not fully expanded.
fn checkpoint_pin_schema() -> Value {
    json!({
        "type": "object",
        "required": ["challenge", "vault_id", "genesis", "checkpoint", "policy", "bindings"],
        "properties": {
            "challenge": byte_array_32_schema("The single-use pairing link's fresh nonce, 32 bytes as 32 numbers."),
            "vault_id": byte_array_32_schema("The vault id, 32 bytes as 32 numbers."),
            "genesis": byte_array_32_schema("The authority genesis entry hash, 32 bytes as 32 numbers."),
            "checkpoint": byte_array_32_schema("The unsigned checkpoint image id, 32 bytes as 32 numbers."),
            "policy": {"type": "object", "description": "The eligible roots and quorum (CheckpointRootPolicy, checkpoint_attest.rs:307-318)."},
            "bindings": {"type": "array", "items": {"type": "object"}, "description": "One certified checkpoint key per root, ascending by root (AuthorityCheckpointKeyBinding, checkpoint_attest.rs:168-184)."}
        }
    })
}

/// This home for a just added machine: `PairedHome` (`pairing.rs:254-257`):
/// the install's machine id in hex and its sync node id. `None` while this
/// install is no machine yet; the redeem stands without it
/// (`pairing.rs:258-272,341-343`).
fn paired_home_schema() -> Value {
    json!({
        "type": "object",
        "required": ["machine", "sync_node_id"],
        "properties": {
            "machine": {"type": "string", "description": "This install's machine id in hex."},
            "sync_node_id": {"type": "integer", "minimum": 0, "description": "This install's sync node id, as oneiron whoami prints it."}
        }
    })
}

/// The OAuth exchange body: `OAuthExchange` (`pairing.rs:92-97`, denied
/// unknown fields `pairing.rs:91`). Binding key, nonce and signature are
/// required; the lifetime is optional caller narrowing, never an override
/// of the vault or JWT ceiling (`pairing.rs:96-97`). The binding key is 64
/// hex and the signature is 128 hex (`pairing.rs:124,127-128`).
fn oauth_body() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["binding_key", "nonce", "signature"],
        "properties": {
            "binding_key": {"type": "string", "description": "The holder's fresh signing key id, 64 lower hex."},
            "nonce": {"type": "string", "description": "The fresh nonce bound into the OAuth binding transcript."},
            "signature": {"type": "string", "description": "The binding signature over the transcript, 128 lower hex."},
            "lifetime_secs": {"type": "integer", "minimum": 0, "description": "Caller narrowing for the minted slip lifetime; never past the JWT remainder."}
        }
    })
}

/// The revoke body: `RevokeSlip` (`pairing.rs:489-490`, denied unknown
/// fields `pairing.rs:488`): the slip id as 32 numbers (a `[u8; 32]` JSON
/// array, not a hex string).
fn revoke_body() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["slip_id"],
        "properties": {
            "slip_id": byte_array_32_schema("The capability slip id, 32 bytes as 32 numbers (not hex).")
        }
    })
}

/// The revoke answer: `revoke` answers `{"revoked": true}`
/// (`pairing.rs:492-499`) once the slip is revoked. Always true.
fn revoked_answer() -> Value {
    json!({
        "type": "object",
        "required": ["revoked"],
        "properties": {
            "revoked": {"type": "boolean", "example": true, "description": "Always true; the slip is revoked."}
        }
    })
}
