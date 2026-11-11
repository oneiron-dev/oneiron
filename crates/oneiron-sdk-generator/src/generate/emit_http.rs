//! The one client artifact, `packages/oneiron-client/src/facade.ts`: the typed facade tree over an injected transport,
//! with its row metadata (OF-246), and each call's invocation id and the pending ask a retry resends under it (OF-580).

use std::sync::LazyLock;

use regex::Regex;

use super::Generator;
use super::emit_ts::{VerbTree, row_of, row_type, ts_doc, ts_input, verb_tree};
use super::row_access::{item, json};
use crate::error::GenerateError;
use crate::py::json::dumps_str;
use crate::py::re::compile_fullmatch;
use crate::py::value::Value;

/// Python's `re.fullmatch(r'[A-Za-z_$][\w$]*', name)`: a segment TypeScript takes as a bare key.
/// Rust: `\A(?:[A-Za-z_$][\p{L}\p{N}_$]*)\z` (`compile_fullmatch`).
static BARE_KEY: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[A-Za-z_$][\w$]*"));

/// The facade tree literal: an arrow per verb over the injected transport, a nested literal per namespace. A node's
/// children are emitted before its own verb, as Python evaluates them.
fn http_members(
    generator: &mut Generator,
    tree: &VerbTree,
    depth: usize,
) -> Result<String, GenerateError> {
    let pad = "  ".repeat(depth);
    let mut out = String::new();
    for (name, node) in tree {
        let key = if BARE_KEY.is_match(name) {
            name.clone()
        } else {
            dumps_str(name)
        };
        let inner = http_members(generator, &node.children, depth + 1)?;
        if let Some(id) = node.row {
            let row = row_of(generator, id);
            let verb = json(item(&row, "name")?);
            let mut value = format!(
                "({}, options?: O): FacadeReturns<{verb}>[K] => invoke({verb}, input, options, newInvocation())",
                ts_input(generator, &row)?
            );
            if !node.children.is_empty() {
                value = format!("Object.assign({value}, {{\n{inner}{pad}}})");
            }
            if row.get("description").is_some_and(Value::truthy) {
                out += &format!("{pad}{}\n", ts_doc(&row));
            }
            out += &format!("{pad}{key}: {value},\n");
        } else {
            out += &format!("{pad}{key}: {{\n{inner}{pad}}},\n");
        }
    }
    Ok(out)
}

/// The row-metadata interface and the head of `FACADE_CATALOG`.
const CATALOG_HEAD: &str = r#"/** One row of the verb table, as a client reads it. */
export interface FacadeVerbMeta {
  /** The row's one line, the same text the MCP tool list serves. */
  readonly description: string;
  /** The credential scope the verb needs. */
  readonly scope: "Read" | "Write";
  /** A write that lands at the actor's ceiling: under `proposed` it waits for review. */
  readonly proposes: boolean;
  /** Answered from the server's own state; an embedded handle may refuse it. */
  readonly hostDoor: boolean;
  /** The verb's result is a board section. */
  readonly section: boolean;
}
/** Every facade verb's row metadata, from the verb table. */
export const FACADE_CATALOG: { readonly [V in FacadeVerb]: FacadeVerbMeta } = {
"#;

/// The end of `FACADE_CATALOG`, the invocation and pending-ask types, and the head of `facadeTree`.
const TREE_HEAD: &str = r#"};

/**
 * A fresh invocation id for one new verb call (ARCH-0080 §3): 32 lowercase hex
 * digits from `crypto.getRandomValues`. The server fires a verb's hooks once
 * per id, and a retry that names the same id is the same call.
 */
export function newInvocation(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
/** A verb hook's stop, as the server's refusal names it in `error.hook`. */
export type FacadeHookStop =
  | { status: "skipped"; hook: string; reason: string }
  | { status: "pending"; invocation: string; ask: string }
  | { status: "hidden"; hook: string };
/** The server's refusal envelope, `{error, narrowing?}`, as `api/facade.rs` writes it. */
export interface FacadeErrorEnvelope {
  error: { code: string; message: string; requestId: string; suggestions: string[]; receiptRef?: string; hook?: FacadeHookStop; retryAfter?: number; resetsAt?: number[]; reasonCodes?: string[]; legal_hold?: Facade.LegalHoldNotice; room_join_hold?: Facade.RoomJoinHold; [field: string]: unknown };
  narrowing?: unknown;
}
/**
 * A call a verb hook stopped on an ask: the server answered `202 PENDING_ASK`
 * and the verb did not run. `invocation` is the id the call ran under and `ask`
 * the ask's handle. `facadeRetry` resends `verb` and `input` under that id: it
 * answers this same pending while the ask is open, and runs the saved call once
 * the ask is answered proceed.
 */
export interface FacadePending<V extends FacadeVerb = FacadeVerb> {
  readonly kind: "pending";
  readonly verb: V;
  readonly input: FacadeInput<V>;
  readonly invocation: string;
  readonly ask: string;
  readonly envelope: FacadeErrorEnvelope;
}

/**
 * What one call answers, by the kind of transport behind the tree: the HTTP
 * adapter's original `Response`, unread; an adapter that decodes, the typed
 * result; an in-process synchronous one, the typed result itself. Every kind
 * answers a `FacadePending` instead for a call a verb hook stopped on an ask,
 * which `facadeRetry` resends.
 */
export interface FacadeReturns<V extends FacadeVerb> {
  response: Promise<Response | FacadePending<V>>;
  result: Promise<FacadeResult<V> | FacadePending<V>>;
  sync: FacadeResult<V> | FacadePending<V>;
}
export type FacadeReturn = keyof FacadeReturns<FacadeVerb>;
/**
 * The one injected invocation: a verb, its typed input, the transport's own
 * options and the call's invocation id, fresh for each call the tree makes and
 * the stopped call's own on a retry, with the ask handle that call stopped on.
 * The transport sends the id with the call (HTTP: `x-oneiron-invocation`), and
 * the ask beside it when there is one (HTTP: `x-oneiron-hook-ask`), so the
 * server resumes that hook pause rather than opening a second one; a pause it
 * no longer holds refuses rather than running as a new call.
 */
export type FacadeTransport<K extends FacadeReturn, O = RequestInit> = <V extends FacadeVerb>(verb: V, input: FacadeInput<V>, options: O | undefined, invocation: string, ask?: string) => FacadeReturns<V>[K];

/**
 * The facade as its path tree (`vault.claims.upsert`, `self.memory.diary`),
 * every verb typed from the verb table, over one injected transport. The HTTP
 * adapter, a native adapter and the code-mode inject each supply theirs.
 */
export function facadeTree<K extends FacadeReturn, O = RequestInit>(invoke: FacadeTransport<K, O>) {
  return {
"#;

/// The end of `facadeTree`, and `facadeRetry`.
const TREE_TAIL: &str = r#"  };
}
export type FacadeTree<K extends FacadeReturn, O = RequestInit> = ReturnType<typeof facadeTree<K, O>>;

/** Retries the call `pending` names through `invoke`: its verb and input, under its own invocation id, naming the ask it stopped on. */
export function facadeRetry<K extends FacadeReturn, O, V extends FacadeVerb>(invoke: FacadeTransport<K, O>, pending: FacadePending<V>, options?: O): FacadeReturns<V>[K] {
  return invoke(pending.verb, pending.input, options, pending.invocation, pending.ask);
}
"#;

/// `json.dumps(bool(value))` of a row's optional flag.
fn json_flag(value: Option<&Value>) -> &'static str {
    if value.is_some_and(Value::truthy) {
        "true"
    } else {
        "false"
    }
}

/// The facade tree over `FACADE_ROWS`, its input and result maps, and its row metadata.
pub(crate) fn http_facade(generator: &mut Generator) -> Result<String, GenerateError> {
    let facade_rows = generator.facade_rows.clone();
    let mut out = format!(
        "{}import type * as Facade from \"./facade-types.js\";\n\n",
        super::HEADER
    );
    out += "/** Every facade verb, in table order. */\n";
    let mut names = Vec::new();
    for &id in &facade_rows {
        names.push(item(&generator.rows[id], "name")?.clone());
    }
    out += &format!(
        "export const FACADE_VERBS = {} as const;\n",
        json(&Value::List(names))
    );
    out += "export type FacadeVerb = typeof FACADE_VERBS[number];\n\n";
    out += "/** Each verb's request body, as its Rust input type reads it. */\nexport interface FacadeInputs {\n";
    for &id in &facade_rows {
        let row = row_of(generator, id);
        let name = json(item(&row, "name")?);
        let input = generator
            .inventory_mut()?
            .ts_type(row_type(&row, "input")?, "Facade.")?;
        out += &format!("  {name}: {input};\n");
    }
    out += "}\n";
    out += "/** Each verb's result: the JSON body of its 2xx response, as its Rust output type writes it. */\nexport interface FacadeResults {\n";
    for &id in &facade_rows {
        let row = row_of(generator, id);
        let name = json(item(&row, "name")?);
        let output = generator
            .inventory_mut()?
            .ts_type(row_type(&row, "output")?, "Facade.")?;
        out += &format!("  {name}: {output};\n");
    }
    out += "}\n";
    out += "export type FacadeInput<V extends FacadeVerb> = FacadeInputs[V];\n";
    out += "export type FacadeResult<V extends FacadeVerb> = FacadeResults[V];\n\n";
    out += CATALOG_HEAD;
    for &id in &facade_rows {
        let row = &generator.rows[id];
        let name = json(item(row, "name")?);
        let no_description = Value::Str(String::new());
        let description = json(row.get("description").unwrap_or(&no_description));
        let scope = json(item(row, "scope")?);
        let proposes = json_flag(row.get("proposes"));
        let host_door = json_flag(row.get("host_door"));
        let section = json_flag(Some(item(row, "section")?));
        out += &format!(
            "  {name}: {{ description: {description}, scope: {scope}, proposes: {proposes}, hostDoor: {host_door}, section: {section} }},\n"
        );
    }
    out += TREE_HEAD;
    let tree = verb_tree(generator, &facade_rows)?;
    out += &http_members(generator, &tree, 2)?;
    out += TREE_TAIL;
    Ok(out)
}
