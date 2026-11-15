#!/usr/bin/env python3
"""Moves hand-written host doors onto generated ones (UC-01 PR 1; fable/19 DESIGN section 4, seeded from the census
script work/door_census.py of that pass).

Usage: python3 scripts/refactor/tools/door_from_row.py [--apply] <door file>... (paths under crates/oneiron-server/src,
run from the repository root).

For each door fn in each file whose verb row says "door": "hand", it prints the old body beside the row edit and the
door the generator emits, after checking four facts against the row (DESIGN section 4): the same callee and arguments,
the same rule, the same handle (the new call says `memory` exactly when the old door read through the credential's
handle) and the same rows. A door of a shape it does not know, or on a setting verb (SETTING_HELD), is refused and
left as it is, with the reason. With --apply it rewrites each accepted row (the three substitutions of DESIGN section
1.3 in `call`, `"door": "hand"` dropped) and deletes each accepted door fn with its doc comment. It edits no
`use` line: the build's unused-import warnings name the ones a move leaves.

Known shapes (WRAPPERS; each wrapper proves the owner with `facade_owner`, as rule `owner` does, and a refusal or a
join error answers as `refused` does):
- `as_owner(server, auth, "<verb>", move |memory, owner| <call>)` of host_doors/support/owner_listing.rs, and the
  file-local one of result_doors.rs: on the credential's handle as its own principal (`facade_actor`), listing what the
  handle read; rule `owner` on the handle.
- `as_owner_naming(server, auth, "<verb>", move |server, owner| <call>, |_| Vec::new())` of legal_hold_doors.rs, and
  the file-local `as_custody_owner(.., move |vault, owner| <call>)` of custody_drain_doors.rs: off the runtime with no
  handle, listing no row.
- the file-local `owned_control(.., move |vault, owner| <call>)` of drafter_doors.rs and `as_owner_listing(..,
  move |server, owner| <call>)` of widen_proposal_doors.rs: the same, with the engine's error mapped into a
  MemoryError by the wrapper, where the row's call maps it itself.
With --apply it names each file-local wrapper that no door of its file calls any more (`## UNUSED`).
"""
import collections
import json
import pathlib
import re
import sys

SERVER = pathlib.Path("crates/oneiron-server/src")
VERBS = pathlib.Path("scripts/sdk/verbs")

# The bound names of a row's call (crates/oneiron-sdk-generator/src/generate/emit_doors.rs BOUND_NAMES), in the order
# a `calls` fn takes them.
BOUND_NAMES = ["memory", "vault", "owner", "surface", "input", "server", "answer"]

# A known wrapper: the closure parameters it hands the call, whether the call reads through the credential's handle,
# the error map it applies to the call's result (which the row's call writes itself), and whether it takes a rows
# closure after the call.
Wrapper = collections.namedtuple("Wrapper", "params on_handle error_map rows_closure")

# The engine's `oneiron::Result` mapped into the door's MemoryResult, as a row's call writes it.
MEMORY_ERROR_MAP = ".map_err(crate::memory::MemoryError::from)"

# Each known wrapper by its full path: the path a door file's `use` line resolves to, or `<module>::<name>` for a fn
# of the door file itself. Each was read to its call (UC-01 PR 2.1; its read leg's shapes W4, W7, W8 and W9).
WRAPPERS = {
    "crate::api::facade::host_doors::support::owner_listing::as_owner": Wrapper(("memory", "owner"), True, "", False),
    "crate::api::facade::legal_hold_doors::as_owner_naming": Wrapper(("server", "owner"), False, "", True),
    "crate::api::facade::result_doors::as_owner": Wrapper(("memory", "owner"), True, "", False),
    "crate::api::facade::custody_drain_doors::as_custody_owner": Wrapper(("vault", "owner"), False, "", False),
    "crate::api::facade::drafter_doors::owned_control": Wrapper(("vault", "owner"), False, MEMORY_ERROR_MAP, False),
    "crate::api::facade::widen_proposal_doors::as_owner_listing": Wrapper(
        ("server", "owner"), False, MEMORY_ERROR_MAP, False
    ),
}

# The 31 pure doors on setting verbs (UC-01 plan, U1-A2: fable/15's setting tables joined with fable/19's door
# census). A Setting stage deletes or keeps each of them, so each stays hand-written until Setting stages 1 to 3
# have landed; a kept one moves in a later PR.
SETTING_HELD = frozenset({
    "vault.agents.plan_mode.set", "vault.code.origin.lfs_path_policy.get", "vault.code.origin.lfs_path_policy.set",
    "vault.commitments.reminder_route.get", "vault.commitments.reminder_route.set", "vault.drafters.policy.set",
    "vault.drafters.status", "vault.free_time.policy.get", "vault.free_time.policy.set",
    "vault.free_time.policy.set_as", "vault.retrieval.policy.get", "vault.retrieval.policy.pin", "vault.sieve.cadence",
    "vault.sieve.policy", "vault.sieve.policy.set", "vault.sieve.recipe_policy", "vault.sieve.recipe_policy.set",
    "vault.skills.advisory_ask.set", "vault.skills.code_auto_install.set", "vault.skills.fit.set",
    "vault.skills.optimize.preferences.get", "vault.skills.optimize.preferences.set",
    "vault.sync.retained_work.wait.set", "vault.trusted_contacts.consent", "vault.trusted_contacts.dial.set",
    "vault.trusted_contacts.list", "vault.trusted_contacts.name", "vault.trusted_contacts.revoke",
    "vault.weave.schedules.clear", "vault.weave.schedules.list", "vault.weave.schedules.put",
})

# A string or char literal, whose whitespace is part of its value.
LITERAL = re.compile(r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])')")

# A raw string literal, which the migrator does not read.
RAW_STRING = re.compile(r'(?<!\w)b?r#*"')

# A door fn with its doc comment and attributes, and the blank and plain `//` lines between them, which go with it when
# it is deleted (Sol review of UC-01 PR 1, F2: a doc cut off by a blank line was left behind).
FN = re.compile(
    r"^(?P<doc>(?:[ \t]*(?:///|#\[)[^\n]*\n(?:[ \t]*(?://(?![/!])[^\n]*)?\n)*)*)pub\(crate\) async fn (?P<name>\w+)\s*\(",
    re.M,
)


def refuse(reason):
    raise ValueError(reason)


def blank_strings(text):
    return re.sub(r'"(\\.|[^"\\])*"', lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', text)


def self_bound(text):
    bound = set()
    for m in re.finditer(r"\blet\b([^=]*)=", text):
        bound.update(re.findall(r"[A-Za-z_]\w*", m.group(1)))
    for m in re.finditer(r"(?:^|move|[(,=])\s*\|([^|]*)\|", text):
        bound.update(re.findall(r"[A-Za-z_]\w*", m.group(1)))
    return bound


def format_captures(expr):
    """The generator's `format_captures`: the bound names a string literal names inside its braces (`{input}`)."""
    captured = set()
    for literal in re.findall(r'"((?:\\.|[^"\\])*)"', expr):
        for group in literal.replace("{{", "").split("{")[1:]:
            captured.update(n for n in re.findall(r"(?<![0-9])[A-Za-z_]\w*", group.split("}")[0]) if n in BOUND_NAMES)
    return captured


def free_names(expr):
    """The generator's `free_names`: each bound name standing alone, not a path segment, field, path head, lifetime
    or struct field name, and not bound by the expression itself."""
    text = blank_strings(expr)
    own = self_bound(text)
    used = set()
    for m in re.finditer(r"(?<![0-9])[A-Za-z_]\w*", text):
        name = m.group(0)
        if name not in BOUND_NAMES or name in own:
            continue
        before, after = text[: m.start()].rstrip(), text[m.end():].lstrip()
        if before.endswith("::") or before.endswith(".") or text[: m.start()].endswith("'"):
            continue
        if after.startswith("::") or (after.startswith(":") and not after.startswith("::")):
            continue
        used.add(name)
    return used


def balanced(text, start, open_ch, close_ch):
    """The index just past the bracket that closes the one at `start`, skipping string literals."""
    depth, at = 0, start
    while at < len(text):
        ch = text[at]
        if ch == '"':
            at += 1
            while text[at] != '"':
                at += 2 if text[at] == "\\" else 1
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return at + 1
        at += 1
    refuse("unbalanced brackets")


def split_args(text):
    """Top-level comma-separated parts of `text`."""
    parts, depth, cur, at = [], 0, "", 0
    while at < len(text):
        ch = text[at]
        if ch == '"':
            end = at + 1
            while text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            cur += text[at : end + 1]
            at = end + 1
            continue
        if ch == "|" and cur.strip() in ("", "move"):
            # A closure's parameter list: its commas separate parameters, not arguments.
            end = text.index("|", at + 1)
            cur += text[at : end + 1]
            at = end + 1
            continue
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
        at += 1
    if cur.strip():
        parts.append(cur.strip())
    return parts


def module_path(path):
    """The module path of a source file under SERVER (`crate::api::facade::free_time_doors`)."""
    parts = list(path.relative_to(SERVER).with_suffix("").parts)
    if parts[-1] in ("mod", "lib", "main"):
        parts.pop()
    return "::".join(["crate", *parts])


def absolute(path, module):
    """A `use` path written from `module` (`super::x`, `self::x`, `crate::x`) as a full `crate::` path; any other path
    (an external crate's) as it is."""
    parts = path.split("::")
    if parts[0] not in ("self", "super"):
        return path
    base = module.split("::")
    while parts[0] in ("self", "super"):
        if parts.pop(0) == "super":
            base.pop()
    return "::".join(base + parts)


def use_map(source):
    """Each name a file's `use` lines import, with its path as written (`self` names the module itself)."""
    names = {}
    for m in re.finditer(r"^use ([^;]+);", source, re.M):
        path = " ".join(m.group(1).split())
        brace = path.find("{")
        if brace < 0:
            if "::" in path and " as " not in path:
                names[path.rsplit("::", 1)[1]] = path
            continue
        head = path[: brace].rstrip(":")
        for leaf in split_args(path[brace + 1 : path.rindex("}")]):
            if leaf == "self":
                names[head.rsplit("::", 1)[1]] = head
            elif "::" not in leaf and " as " not in leaf:
                names[leaf] = f"{head}::{leaf}"
    return names


def resolve(expr, names):
    """`expr` with each imported path head written in full, and engine paths as the engine writes them."""
    out = re.sub(
        r"(?<![\w:.])([A-Za-z_]\w*)(?=\s*(::|\())",
        lambda m: names.get(m.group(1), m.group(1)) if names.get(m.group(1), "").startswith("oneiron::") else m.group(1),
        expr,
    )
    return out.replace("oneiron::", "crate::")


def squash(text):
    """`text` without whitespace outside its string and char literals (Astra review of UC-01 PR 1, F2)."""
    parts = LITERAL.split(text)
    return "".join(part if at % 2 else re.sub(r"\s+", "", part) for at, part in enumerate(parts))


def call_result(call):
    return call[:-1] if call.endswith("?") else f"Ok({call})"


def new_call(row):
    """The row's call after the three substitutions of DESIGN section 1.3."""
    call = row["call"]
    owner = f'&memory.embedded_owner({json.dumps(row["name"])})?'
    return (
        call.replace(owner, "owner")
        .replace("memory.vault()", "vault")
        .replace("crate::authority::ActSurface::ThisInstall", "surface")
    )


def generated_door(row, call):
    """The door the generator emits for `row` (emit_doors.rs `doors`), as a reading aid."""
    names = free_names(call)
    method = row["name"].replace(".", "_")
    helper = "door_on_handle" if "memory" in names else "door"
    server = "server" if "vault" in names else "_"
    owner = "owner" if "owner" in names else "_"
    params = f"{server}, memory, {owner}" if "memory" in names else f"{server}, {owner}"
    args = ", ".join("server.vault()" if n == "vault" else n for n in BOUND_NAMES if n in names)
    return (
        f"{helper}::<proofs::Owner, _>(server, auth, {json.dumps(row['name'])}, move |{params}| "
        f"calls::{method}({args}))"
    )


def check_door(source, match, rows, names, module):
    """The row edit for one door fn, or a refusal naming why it stays hand-written."""
    name = match.group("name")
    end = balanced(source, source.index("{", match.end()), "{", "}")
    text = source[match.start() : end]
    verb = next((v for v in rows if v.replace(".", "_") == name), None)
    if verb is None:
        refuse("no verb row names this fn")
    row = rows[verb]
    if row.get("door") != "hand":
        refuse('the row has no "door": "hand"')
    if verb in SETTING_HELD:
        refuse("a setting verb (U1-A2): its door stays hand-written until Setting stages 1 to 3 have landed")
    if row.get("proof") != "owner":
        refuse(f"rule `{row.get('proof')}` has no generated door yet")
    for flag in ("host_door_caller", "host_door_session", "host_door_paced", "host_door_lens_owner",
                 "host_door_client_surface", "rust_feature", "file_call", "rows"):
        if row.get(flag):
            refuse(f"the row has `{flag}`")
    if not row.get("lists"):
        refuse("the row does not list its rows")
    open_at = match.end() - 1
    close_at = balanced(source, open_at, "(", ")")
    params = split_args(source[open_at + 1 : close_at - 1])
    expected = ["server: &Arc<SyncServer>", "auth: &CoreAuth"]
    if row.get("host_door_surface"):
        expected.append("surface: oneiron::authority::ActSurface")
    if [squash(p) for p in params[: len(expected)]] != [squash(p) for p in expected] or len(params) != len(expected) + 1:
        refuse(f"parameters {params} are not {expected} and the input")
    body = source[source.index("{", close_at) : end].strip()[1:-1].strip()
    wrapper = re.match(r"(\w+)\s*\(", body)
    if not wrapper:
        refuse("its body is not one known wrapper call")
    # The whole path, resolved from this file's module: a suffix match takes any wrapper of that name (F3).
    path = wrapper_path(source, wrapper.group(1), names, module)
    if path not in WRAPPERS:
        refuse(f"its body is not one known wrapper call (`{wrapper.group(1)}`: {path or 'not imported, not its own'})")
    known = WRAPPERS[path]
    close = balanced(body, wrapper.end() - 1, "(", ")")
    if squash(body[close:]) != ".await":
        refuse("the wrapper call is not the whole body")
    args = split_args(body[wrapper.end() : close - 1])
    want = 5 if known.rows_closure else 4
    if len(args) != want or args[:2] != ["server", "auth"] or args[2] != json.dumps(verb):
        refuse(f"wrapper arguments {args[:3]} are not server, auth, the verb")
    if want == 5 and squash(args[4]) != "|_|Vec::new()":
        refuse("its rows closure names rows")
    closure = re.match(r"move\s*\|([^|]*)\|\s*(.*)$", args[3], re.S)
    if not closure or [p.strip() for p in closure.group(1).split(",")] != list(known.params):
        refuse(f"its call closure takes {closure.group(1) if closure else '?'}, not {known.params}")
    door_call = closure.group(2).strip()
    if door_call.startswith("{") and door_call.endswith("}"):
        door_call = door_call[1:-1].strip()
    door_call = resolve(door_call, names).replace("server.vault()", "vault") + known.error_map
    if "server" in free_names(door_call):
        refuse("its call reads the server beyond its vault")
    call = new_call(row)
    if RAW_STRING.search(blank_strings(door_call)) or RAW_STRING.search(blank_strings(call)):
        refuse("its call has a raw string literal, which the migrator does not read")
    if format_captures(call):
        refuse("its call names a bound name inside a string (a format capture), which the generator refuses")
    if squash(call_result(call)) != squash(door_call):
        refuse(f"its call `{door_call}` is not the row's `{call_result(call)}`")
    if ("memory" in free_names(call)) != known.on_handle:
        refuse("the row's call reads the handle exactly when the old door did not")
    return dict(verb=verb, text=text, start=match.start(), end=end, call=call,
                door=generated_door(row, call), wrapper=wrapper.group(1), wrapper_path=path)


def wrapper_path(source, name, names, module):
    """The full path of the wrapper `name` a door in `source` calls: its `use` line's, or `<module>::<name>` for an
    `async fn` of the file itself; "" for neither."""
    if name in names:
        return absolute(names[name], module)
    if re.search(rf"^(?:pub\([^)]*\) )?async fn {re.escape(name)}\b", source, re.M):
        return f"{module}::{name}"
    return ""


def main(argv):
    apply = "--apply" in argv
    paths = [a for a in argv if a != "--apply"]
    rows = {}
    files = {}
    for path in sorted(VERBS.glob("*.json")):
        row = json.loads(path.read_text())
        rows[row["name"]] = row
        files[row["name"]] = path
    moved = refused = 0
    for door_file in paths:
        path = pathlib.Path(door_file)
        if SERVER not in path.parents:
            return f"{path} is not under {SERVER}"
        source = path.read_text()
        names = use_map(source)
        module = module_path(path)
        accepted = []
        for match in FN.finditer(source):
            try:
                edit = check_door(source, match, rows, names, module)
            except ValueError as reason:
                refused += 1
                print(f"## HAND {path}:{source.count(chr(10), 0, match.start()) + 1} {match.group('name')}: {reason}")
                continue
            accepted.append(edit)
            row = rows[edit["verb"]]
            print(f"## MOVE {path}:{source.count(chr(10), 0, match.start()) + 1} {edit['verb']} ({edit['wrapper']}, "
                  f"rule owner, {'handle' if 'memory' in free_names(edit['call']) else 'no handle'}, rows none)")
            print("old door:\n" + edit["text"])
            print(f"row call: {row['call']}\n      ->  {edit['call']}\nrow: drop \"door\": \"hand\"")
            print(f"generated: {edit['door']}\n")
        moved += len(accepted)
        if not apply or not accepted:
            continue
        for edit in accepted:
            row = dict(rows[edit["verb"]])
            row["call"] = edit["call"]
            del row["door"]
            files[edit["verb"]].write_text(json.dumps(row, indent=2, ensure_ascii=False) + "\n")
        for edit in sorted(accepted, key=lambda e: -e["start"]):
            head, rest = source[: edit["start"]].rstrip("\n"), source[edit["end"] :].lstrip("\n")
            if not head:
                source = rest
            elif rest:
                source = head + "\n\n" + rest
            else:
                source = head + "\n"
        path.write_text(source)
        if not FN.search(source):
            print(f"## EMPTY {path}: no door fn is left; delete the file and its `mod` and `use` lines")
            continue
        for wrapper in sorted({e["wrapper"] for e in accepted if e["wrapper_path"] == f"{module}::{e['wrapper']}"}):
            if not re.search(rf"(?<!fn )\b{wrapper}\s*\(", source):
                print(f"## UNUSED {path}: no door calls its own `{wrapper}` any more; delete it")
    print(f"## DONE moved={moved} hand={refused} applied={'yes' if apply else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
