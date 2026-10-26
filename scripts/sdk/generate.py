#!/usr/bin/env python3
'Generate agent SDK transports from agent-verbs.json; --check never writes.'
import argparse
import functools
import json
import keyword
import re
import subprocess
from facade_types import Inventory
from catalog_fragment import catalog_fragment
from uniffi_types import UniffiTypes
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((Path(__file__).with_name('agent-verbs.json')).read_text())
# Run and browser rows may expose a typed host door beside their code-mode
# shape. The host projection adds the caller's credential-bound live-run
# attachment; code mode keeps the original input and run-owned resource.
HOST_ROWS = [row for row in MANIFEST['verbs'] if 'host' in row]
HOST_RUN_ROWS = [row for row in HOST_ROWS if row.get('context') == 'run']
HOST_BROWSER_ROWS = [row for row in HOST_ROWS if row.get('context') == 'browser']
# A board row keeps its MCP/code-mode shape in ROWS (its board fn, tool
# schema and run door read the original input); its host projection is a
# facade-only row beside it (BOARD_HOST_ROWS), never a replacement.
HOST_BOARD_ROWS = [row for row in HOST_ROWS if row.get('context') == 'board']
BROWSER_ROWS = [row for row in MANIFEST['verbs'] if row.get('context') == 'browser']
for row in HOST_ROWS:
    host = row['host']
    if (row.get('context') not in ('run', 'browser', 'board') or not {'input', 'description'} <= set(host)
            or set(host) - {'input', 'output', 'description', 'host_door_caller', 'host_door_session', 'host_door_lists', 'openapi'}
            or ('output' in host and row.get('context') != 'board')
            or any(not isinstance(host[key], bool) for key in ('host_door_caller', 'host_door_session', 'host_door_lists', 'openapi') if key in host)):
        raise ValueError(f'{row["name"]}: a host projection names the public input and description, with optional caller, session, lists and OpenAPI flags')
def host_synthetic(row):
    return {'name': row['name'], 'input': row['host']['input'],
     'output': row['host'].get('output', row['output']),
     'description': row['host']['description'], 'scope': row['scope'],
     'call': f'crate::task_verb::sdk::host_only(memory, "{row["name"]}", &input)?',
     'host_door': True, 'host_door_session': row['host'].get('host_door_session', True),
     'host_door_caller': row['host'].get('host_door_caller', False),
     # A browser door lists its rows; a run projection lists when its host
     # object says so (FIX 4709), its door then answering `Listed` or
     # `MaybeListed` as an explicit host row does.
     'host_door_lists': row.get('context') == 'browser' or row['host'].get('host_door_lists', False),
     'openapi': row['host'].get('openapi', False),
     'admission': {'unrestricted_record_scope': True}, 'section': False}
ROWS = [row for row in MANIFEST['verbs'] if 'call' in row and row not in HOST_BROWSER_ROWS] + [
    host_synthetic(row) for row in HOST_ROWS if row.get('context') != 'board'
]
BOARD_HOST_ROWS = [dict(host_synthetic(row), board_host=True, board_input=row['input'])
                   for row in HOST_BOARD_ROWS]
BOARD_HOST_NAMES = {row['name'] for row in BOARD_HOST_ROWS}
DEFINITIONS = [row for row in MANIFEST['verbs'] if 'call' not in row and 'host' not in row]
if len({row['name'] for row in MANIFEST['verbs']}) != len(MANIFEST['verbs']): raise ValueError('duplicate SDK verb')
RUN_ROWS = [row for row in MANIFEST['verbs'] if row.get('context') == 'run']
# Code mode always reads the run/browser input; the served schema reads its host input.
CODE_MODE_ROWS = [row for row in ROWS if row['name'] not in {r['name'] for r in HOST_ROWS}] + HOST_BROWSER_ROWS + HOST_BOARD_ROWS + RUN_ROWS
SCHEMA_ROWS = ROWS + [row for row in RUN_ROWS if 'host' not in row]
for row in RUN_ROWS:
    if set(row) - {'output', 'outputs_by_input', 'host'} != {'name', 'input', 'scope', 'context', 'effect'} or row['scope'] not in ('Read', 'Write'):
        raise ValueError(f'{row["name"]}: a run row names its input, scope, effect, output and per-input outputs, and nothing else')
# `outputs_by_input` maps an input field, by its wire name, to the reply code
# mode answers when that field is present and not null (`describe({fold})`
# answers the fold, `tasks.update({resultRef})` the reader's report). Each type
# is a Rust path read through the same type inventory as `output`, which stays
# the reply to every other input. Only the catalog fragment reads it: the run
# answers these inputs itself (wire.rs `self_call`) and every host door refuses
# them, so the facade, MCP and binding projections keep the row's `output`.
for row in MANIFEST['verbs']:
    if 'outputs_by_input' not in row: continue
    by_input = row['outputs_by_input']
    if 'output' not in row or not isinstance(by_input, dict) or not by_input or not all(
            isinstance(field, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', field) and isinstance(output, str) and output.strip()
            for field, output in by_input.items()):
        raise ValueError(f'{row["name"]}: outputs_by_input maps input field names to non-empty output types, beside the row\'s own output')
# ARCH-0028: the MCP tool list and the code-mode method table ARE the verb table,
# so a row carries no opt-out. A row's tool takes its whole typed input as `spec`
# unless it names a projection, and refuses a world/facet-narrowed connector
# unless it names a scope it can carry: a new row is listed, and fails closed.
# `born` carries the connector's own world and facet into what it writes: the
# TASK it mints is born there (ARCH-0067 §5).
# The one exception is a `context: "browser"` row: the run's own browser
# session answers it, a host resource code mode binds per run, so it states
# `mcp: "none"` and code mode is its only door. A `context: "scoped_child"`
# row (FIX 7508, L13 10-22) is the other: a port a host lends a scoped child
# it queues (`ScopedChildPorts`), which the child's dispatcher runs on the
# host's adapter. It is in the verb table, the schema table and the code-mode
# catalogue, and in no facade, HTTP or public MCP door; its `call` is the
# host-only refusal an embedded handle answers, and it has no host door.
MCP_NONE_CONTEXTS = ('browser', 'scoped_child')
for row in MANIFEST['verbs']:
    if row.get('context') != 'scoped_child': continue
    if (set(row) - {'description'} != {'name', 'input', 'output', 'call', 'scope', 'context', 'mcp', 'section'}
            or row['scope'] not in ('Read', 'Write') or row['section']
            or row['call'] != f'crate::task_verb::sdk::host_only(memory, "{row["name"]}", &input)?'):
        raise ValueError(f'{row["name"]}: a scoped-child row names its input, output, scope and description, calls the host-only refusal, and nothing else')
MCP_SCOPES = {'filtered', 'unrestricted', 'addressed', 'born'}
for row in ROWS:
    if (row.get('context') in MCP_NONE_CONTEXTS) != (row.get('mcp', 'tool') == 'none'):
        raise ValueError(f'{row["name"]}: only a browser or scoped-child row states "mcp": "none", and every such row does')
    row.setdefault('mcp_fields', {'spec': '$'})
    row.setdefault('mcp_scope', 'unrestricted')
    if row['mcp_scope'] not in MCP_SCOPES: raise ValueError(f'{row["name"]}: mcp_scope must be one of {sorted(MCP_SCOPES)}')
    if any('.' in path for path in row['mcp_fields'].values()): raise ValueError(f'{row["name"]}: an MCP field maps onto one top-level input field')
    # ARCH-0028 propose-only: `proposes` marks a write that lands at the
    # actor's ceiling, so under `proposed` it waits for review. Any other write
    # takes effect at once and needs write capability.
    if row.get('proposes') and row['scope'] != 'Write': raise ValueError(f'{row["name"]}: only a Write row proposes')
    # ARCH-0026 RD-26: `lands_turn` marks a write that lands a conversation
    # turn, so every served door (the HTTP facade and the MCP dispatch, a host
    # door's too) wakes the Dreamer's turn producer after it. A host door that
    # lands its turn itself leaves the flag off.
    if row.get('lands_turn') and row['scope'] != 'Write': raise ValueError(f'{row["name"]}: only a Write row lands a turn')
    if row.get('lands_turn') and row.get('context') == 'board': raise ValueError(f'{row["name"]}: a board verb lands no turn')
    # `host_door` marks a row only a server's own state answers (the owner's
    # proof, its model seats): the HTTP facade and the MCP dispatch both call
    # `api::facade::host_doors::<fn>(server, auth, input)`, and its `call` is
    # what an embedded handle answers instead.
    if row.get('host_door') and (row.get('server_door') or row.get('admission', {}).get('owner_grade') or row.get('context', 'memory') != 'memory'):
        raise ValueError(f'{row["name"]}: a host door is a memory row with no other server door')
    # `host_door_caller` hands the door the caller's own principal (the
    # facade credential's, or the MCP connector's actor) and the logical
    # invocation the call resolved: the one its verb hooks fired for.
    if row.get('host_door_caller') and not row.get('host_door'):
        raise ValueError(f'{row["name"]}: only a host door takes its caller')
    # `host_door_session` hands the door the sitting the call names (the
    # facade's session header, or the MCP connector's off-record session),
    # `None` when it names none; a session that is no id refuses.
    if row.get('host_door_session') and not row.get('host_door'):
        raise ValueError(f'{row["name"]}: only a host door takes its session')
    # `host_door_lists` marks a host door that lists the rows its reads
    # picked, as a plain row's answer does: the door returns them beside its
    # result, and every served door releases the answer by them (DEC-0005).
    # A door one of whose paths lists none returns `None` for that call, never
    # an empty list standing in for it, and the call's answer goes unlisted.
    if row.get('host_door_lists') and not row.get('host_door'):
        raise ValueError(f'{row["name"]}: only a host door lists its rows')
    # `host_door_lens_owner` hands a live lens door the owner its card is held
    # for (OF-181, FIX 2612), never a field of its input: the facade call's
    # host-bound creating run and subscription (`FacadeCall::lens_owner`), or
    # a code-mode call's run and the request's own subscription
    # (`McpRowSurface::lens_owner`). A door handed `None` holds its card
    # unowned, as every HTTP call and direct tool call does.
    if row.get('host_door_lens_owner') and not row.get('host_door'):
        raise ValueError(f'{row["name"]}: only a host door takes a lens owner')
    # `host_door_surface` hands an owner-setting door where the owner's say-so
    # reached this install, for his act's audit record (FIX 4625): the facade
    # call's request-derived surface (`FacadeCall::surface`, a linked machine
    # its headers prove), or the header-less rule for an MCP row
    # (`owner_binding::act_surface`). Never a field of its input.
    if row.get('host_door_surface') and not row.get('host_door'):
        raise ValueError(f'{row["name"]}: only a host door takes an act surface')
    # Rule 5: `task_work` marks a row whose run is one piece of task work. The
    # server's dispatch and its MCP dispatch take one turn for it
    # (`SyncServer::admit_task_work`, never refused) before the engine call,
    # bind it on the surface that call runs on, so the engine's task work
    # waits for no other, and hold it until the call returns. Only a plain
    # memory row's doors all reach that one engine call.
    if row.get('task_work') and (row.get('host_door') or row.get('server_door') or row.get('admission', {}).get('owner_grade')
                                 or 'rows' in row.get('admission', {}).get('readable', []) or row.get('context', 'memory') != 'memory'):
        raise ValueError(f'{row["name"]}: task work is a plain memory row')
    # DOOR-115: `openapi` publishes a facade row in the server's OpenAPI
    # document, at `POST /v1/core/facade/<name>`, with its typed request
    # (`input_schema`) and its typed answer (`output_schema`, read from the
    # row's `output` type, which derives `JsonSchema`). Only a facade row has
    # that route.
    if row.get('openapi') and row.get('context', 'memory') != 'memory':
        raise ValueError(f'{row["name"]}: only a facade row is published in OpenAPI')
    # A JSON attachment keeps the row's typed body and its declared filename.
    if 'attachment' in row and (row.get('context', 'memory') != 'memory'
            or not isinstance(row['attachment'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', row['attachment'])):
        raise ValueError(f'{row["name"]}: an attachment names a facade JSON response file')
    # DOOR-127: `no_record` marks a facade row no transport keeps a call
    # receipt of (`NO_RECORD_ROWS`): an off-record session's own rows, as
    # ARCH-0052 keeps no wire receipt that a session ran. Every reply states
    # `none; no-record`, as the owner's off-record routes do. Only a host door
    # judged by the owner's proof carries it, so no other caller's call goes
    # unrecorded.
    if row.get('no_record') and (row.get('context', 'memory') != 'memory' or not row.get('host_door')):
        raise ValueError(f'{row["name"]}: only a host-door facade row keeps no call receipt')
    # FIX 6498: `require_granted_scope` marks a write whose engine door judges
    # the credential's own read lane in every snapshot it reads and writes, so
    # its facade head checks the grant alone and its lane guard
    # (`lane_record_scope`) keeps refusing a channel caveat: a world-, facet-
    # or record-scoped credential reaches it over HTTP as over MCP. FIX 6867
    # (G1 PR3b): a caller or listing host door may carry it too (the public
    # `vault.repo.*` run doors), its host head then checking the grant alone.
    admission = row.get('admission', {})
    if admission.get('require_granted_scope') and (
            not admission.get('lane_record_scope') or row.get('scope') == 'Read'
            or (row.get('host_door') and not (row.get('host_door_caller') or row.get('host_door_lists')))
            or row.get('context', 'memory') != 'memory'
            or any(admission.get(other) for other in ('owner_grade', 'claim_record_scope', 'credential_record_scope', 'scoped_export', 'born_record_scope'))):
        raise ValueError(f'{row["name"]}: require_granted_scope is only a non-Read lane_record_scope facade row\'s, with no other record-scope admission, and on a host door only a caller or listing one')
# OF-063: `refs` lists a row's typed record-ref slots as JSON pointers into its
# input, `*` taking every item of an array. The row's generated engine fn checks
# that each ref there resolves under the writer's own scoped read before the
# engine call (`record_refs_check`), so every door that reaches the row meets
# the check once. Only a plain memory row's doors all reach that fn. A row's
# `refs_check` swaps in its own checker for those refs (FIX 7566): a Rust path
# to a fn, read only beside nonempty `refs`.
for row in ROWS:
    if 'refs_check' in row and ('refs' not in row or not isinstance(row['refs_check'], str)
            or not re.fullmatch(r'(crate|super|self)(::[A-Za-z_][A-Za-z0-9_]*)+', row['refs_check'])):
        raise ValueError(f'{row["name"]}: refs_check is a Rust fn path (crate::...), and only beside refs')
    if 'refs' not in row: continue
    if row.get('context', 'memory') != 'memory' or row.get('host_door') or row.get('server_door') or row.get('admission', {}).get('owner_grade'):
        raise ValueError(f'{row["name"]}: only a plain memory row checks its record refs in its engine fn')
    pointers = row['refs']
    if not pointers or len(set(pointers)) != len(pointers) or not all(isinstance(p, str) and re.fullmatch(r'(/(\*|[a-z_][a-z0-9_]*))+', p) for p in pointers):
        raise ValueError(f'{row["name"]}: refs are distinct JSON pointers of field names and `*`')
# 2690: a `readable` entry is `rows`, a top-level field, or a nested path of
# fields joined by `.`, any of them suffixed `[*]` to take every item of an
# array (`reviewed[*].artifact_ref`). The facade checks each hex entity id at
# its end with the credential's read check; a top-level field keeps its own
# check, unchanged.
def nested_readable(readable):
    'Whether a `readable` entry is a nested path rather than a top-level field.'
    return '.' in readable or '[' in readable
for row in ROWS:
    for readable in row.get('admission', {}).get('readable', []):
        if readable != 'rows' and not re.fullmatch(r'[a-z_][a-z0-9_]*(\[\*\])?(\.[a-z_][a-z0-9_]*(\[\*\])?)*', readable):
            raise ValueError(f'{row["name"]}: readable entries are `rows` or field paths of `.` and `[*]`')
# OF-063 prose links (Engine ruling 10-17): `prose_links` lists a row's text
# slots, read for `oneiron://` record links before the engine call
# (`prose_links_check`) and receipted only once that call has landed the
# write (`prose_links_landed`, Engine ruling 10-18). A pointer may end at an opaque value (each of its
# strings is read) and `*[key=value]` takes only the array items whose `key`
# is the string `value`, which declares them AI-written. An AI-written link
# that does not resolve for its writer is receipted, never refused.
for row in ROWS:
    if 'prose_links' not in row: continue
    if row.get('context', 'memory') != 'memory' or row.get('host_door') or row.get('server_door') or row.get('admission', {}).get('owner_grade'):
        raise ValueError(f'{row["name"]}: only a plain memory row reads its prose links in its engine fn')
    pointers = row['prose_links']
    if not pointers or len(set(pointers)) != len(pointers) or not all(isinstance(p, str) and re.fullmatch(r'(/(\*(\[[a-z_][a-z0-9_]*=[a-z0-9_]+\])?|[a-z_][a-z0-9_]*))+', p) for p in pointers):
        raise ValueError(f'{row["name"]}: prose_links are distinct JSON pointers of field names, `*` and `*[key=value]`')
# OF-246: `binding.generic` marks a row every typed layer still reaches over
# the generic agent-verb door with its whole input (the remote client, UniFFI,
# napi and the Python native module). Its `args` spell only the positional
# parameters of the package handle's method (`index.ts`, `__init__.py`): each
# names its Rust `type`, read through the type inventory, and the input `field`
# it fills (its own name when absent; `$` is the whole input). An `Option<T>`
# parameter may be left out; a `default` is the string one left out sends. No
# typed projection reads such a binding, so it moves off the row into
# `handle_args` here.
for row in ROWS:
    binding = row.get('binding')
    if not binding or not binding.get('generic'): continue
    args = binding.get('args')
    if set(binding) != {'generic', 'args'} or row.get('context', 'memory') != 'memory' or 'uniffi' in row or not isinstance(args, list):
        raise ValueError(f'{row["name"]}: a generic binding is a memory row\'s `generic` and `args`, with no uniffi signature')
    for a in args:
        if not (isinstance(a, dict) and {'name', 'type'} <= set(a) <= {'name', 'type', 'field', 'default'}
                and re.fullmatch(r'[a-z_][a-z0-9_]*', a['name']) and isinstance(a['type'], str)
                and ('default' not in a or isinstance(a['default'], str) and not a['type'].startswith('Option<'))):
            raise ValueError(f'{row["name"]}: a generic binding arg names its parameter and Rust type, and may name its field and a string default of a type that is no Option')
        if a.get('field') == '$' and (len(args) != 1 or a['type'] != row['input'] or 'default' in a):
            raise ValueError(f'{row["name"]}: a whole-input parameter is the row\'s only one, typed as its input')
    row['handle_args'] = row.pop('binding')['args']
# A callable row's `description` is its one line, said once: the MCP tool
# description, the JSDoc of each TypeScript method and the docstring of each
# Python one. A run row carries none: its key set is fixed above.
for row in MANIFEST['verbs']:
    if 'description' not in row: continue
    text = row['description']
    if 'call' not in row or not isinstance(text, str) or not re.fullmatch(r'[ -~]{1,240}\.', text) or any(s in text for s in ('\\', '"', '*/')):
        raise ValueError(f'{row["name"]}: a description is one printable ASCII line of a callable row, ending in a period, with no backslash, double quote or `*/`')
def mcp_rows():
    'The rows the MCP doors serve as tools: every row but a browser row.'
    return [row for row in ROWS if row.get('mcp') != 'none']
HEADER = '// Generated by scripts/sdk/generate.py; edit agent-verbs.json instead.\n'
FACADE_ROWS = [row for row in ROWS if row.get('context', 'memory') == 'memory'] + BOARD_HOST_ROWS
# OF-246: the wire types every facade row's input and result reach, read from
# the Rust sources the rows name. Every TypeScript and Python projection below
# names its types from here; there is no second table of shapes.
INVENTORY = Inventory(ROOT, FACADE_ROWS)
# Clippy caps a function at seven parameters, its receiver included. A verb
# with more SDK arguments says why it may pass them one by one.
LONG_SIGNATURE = 'expect(clippy::too_many_arguments, reason = "one parameter per SDK argument of the verb")'
def long_signature(params):
    return f'#[{LONG_SIGNATURE}] ' if params > 7 else ''
# OF-495: the Rust primitives a row may name bare; no crate path prefixes them.
RUST_PRIMITIVES = frozenset({'bool', 'char', 'String', 'f32', 'f64', 'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
                             'i8', 'i16', 'i32', 'i64', 'i128', 'isize', '()'})
def rust_type(value):
    'A row type outside the engine: primitives and JSON values as is, engine paths under `oneiron::`, other names from the SDK module.'
    if value in RUST_PRIMITIVES or value == 'serde_json::Value': return value
    return value.replace('crate::', 'oneiron::') if value.startswith('crate::') else 'oneiron::task_verb::sdk::' + value

SERVER_RECALL_DOC = "/// `vault.recall` → `SyncServer::recall_home_listing`, the recall door\n/// every server transport shares (`POST /v1/core/facade/vault.recall`, and\n/// the held socket's `rpc.req`): it embeds the query whenever the vault's\n/// embedder is serving.\n///\n/// The lease is not a client input, and a bearer slip is not one. At high,\n/// xhigh and max the door admits the recall on a line of its own and\n/// reranks on the `[models]` reranker; its refusals (`BUDGET_SPENT`,\n/// `MODEL_UNAVAILABLE`) are forwarded as those exact codes. With no\n/// reranker route the recall runs unreranked and reports\n/// `skipped / no_reranker` in `retrieval_meta.rerank`.\n///\n/// On a device that syncs only what it opened, the door then asks the home\n/// under the call's own caller (FIX 2905): its references ride in\n/// `residence`, apart from the local items; without them the pack is\n/// local-only and `partial`.\n"
# FIX 2905: the server doors that also ask an opened device's home, by row,
# with the caller the call (or the MCP actor) admitted as the last argument.
HOME_SERVER_DOORS = {'vault.recall': 'recall_home_listing'}
# FIX 3876: the rows whose page is read on the transport's own caller surface,
# as a plain row's is, then completed by the opened device's home under the
# caller the call admitted. REST runs the row's facade door (its hooks
# outside, its surface the facade's own); MCP runs the plain arm on its own
# surface and then the home step, which lists the home's references.
CALL_HOME_DOORS = {'vault.search.bm25': ('super::search_home_doors::vault_search_bm25',
                                         'crate::api::search::complete_bm25_with_home')}
# FIX 10425: the facade host-door rows whose answer counts its hooks' verdict
# decisions among its own (`model_free`), as their code-mode door does.
HOOK_DECISION_ROWS = {'self.browser.batch', 'self.browser.library.run'}

# Boundary codecs are selected by argument/result type, never by verb name.
ARGUMENTS = {
    'witness': {'rust': '&oneiron::memory::WitnessTurn', 'napi': 'NapiWitnessTurnInput', 'native_ts': 'WitnessTurn', 'py': 'dict[str, Any]', 'stub': 'WitnessTurn', 'native_py': '&str', 'json': True,
        'napi_convert': 'let {name} = {name}.into_engine()?;', 'py_convert': 'let {name} = decode::<WitnessTurnInput>({name}, "witness turn")?.into_engine().map_err(raise)?;', 'borrow': '&'},
    'claim': {'rust': '&oneiron::memory::ClaimInput', 'napi': 'NapiClaimInput', 'native_ts': 'ClaimInput', 'py': 'dict[str, Any]', 'stub': 'ClaimInput', 'native_py': '&str', 'json': True,
        'napi_convert': 'let {name} = claim_input_to_engine(&{name}).map_err(facade_error)?;', 'py_convert': 'let {name}: ClaimInput = decode({name}, "claim")?;', 'borrow': '&'},
    'text': {'rust': '&str', 'napi': 'String', 'native_ts': 'string', 'py': 'str', 'stub': 'str', 'native_py': 'String', 'borrow': '&', 'field': '{name}.to_owned()'},
    'effort': {'rust': 'oneiron::memory::RecallEffort', 'napi': 'Option<String>', 'native_ts': 'string | undefined', 'py': 'str', 'stub': 'Effort', 'native_py': 'Option<&str>',
        'napi_convert': 'let {name} = oneiron_remote::parse_effort({name}.as_deref().unwrap_or({default})).map_err(facade_error)?;', 'py_convert': 'let {name} = oneiron_remote::parse_effort({name}.unwrap_or({default})).map_err(raise)?;', 'field': 'Some({name})'},
    'scope': {'rust': '&oneiron::memory::RecallScope', 'napi': 'Option<NapiRecallScope>', 'native_ts': 'RecallScope | undefined', 'py': 'dict[str, Any] | None', 'stub': 'RecallScope | None', 'native_py': 'Option<&str>', 'json': True,
        'napi_convert': 'let {name} = recall_scope_to_engine({name});', 'py_convert': 'let {name} = match {name} {{ Some(value) => decode(value, "recall scope")?, None => oneiron::memory::RecallScope::default() }};', 'borrow': '&', 'field': 'Some({name}.clone())'},
    'limit': {'rust': 'usize', 'napi': 'Option<f64>', 'native_ts': 'number | undefined', 'py': 'int', 'stub': 'int', 'native_py': 'Option<usize>',
        'napi_convert': 'let {name} = {name}.map(limit_to_engine).transpose().map_err(facade_error)?.unwrap_or({default});', 'py_convert': 'let {name} = {name}.unwrap_or({default});', 'field': 'Some({name})'},
    'format': {'rust': 'Option<&str>', 'napi': 'Option<String>', 'native_ts': 'string | undefined', 'py': 'str | None', 'stub': 'PackFormat | None', 'native_py': 'Option<String>', 'borrow': '', 'suffix': '.as_deref()', 'field': '{name}.map(str::to_owned)'},
    'as_of': {'rust': 'Option<u64>', 'napi': 'Option<f64>', 'native_ts': 'number | undefined', 'py': 'int | None', 'stub': 'int | None', 'native_py': 'Option<u64>',
        'napi_convert': 'let {name} = {name}.map(|value| oneiron_remote::check_unix_seconds("as_of", value)).transpose().map_err(facade_error)?;', 'field': '{name}'},
    'deadline_ms': {'rust': 'Option<u64>', 'napi': 'Option<f64>', 'native_ts': 'number | undefined', 'py': 'int | None', 'stub': 'int | None', 'native_py': 'Option<u64>',
        'napi_convert': 'let {name} = {name}.map(oneiron_remote::check_deadline_ms_number).transpose().map_err(facade_error)?;', 'field': '{name}'},
    # OF-370: a recall's media query, lowered from each boundary's own record
    # (napi object, UniFFI record, Python JSON) onto the engine's wire type.
    'media': {'rust': 'Option<oneiron::code_run::vault_read::ContextPackMediaQuery>', 'napi': 'Option<NapiRecallMedia>', 'native_ts': 'RecallMedia | undefined', 'py': 'dict[str, Any] | None', 'stub': 'RecallMedia | None', 'native_py': 'Option<&str>', 'json': True,
        'napi_convert': 'let {name} = {name}.map(recall_media_to_engine).transpose().map_err(facade_error)?;', 'py_convert': 'let {name}: Option<oneiron::code_run::vault_read::ContextPackMediaQuery> = {name}.map(|value| decode(value, "recall media")).transpose()?;', 'field': '{name}'},
    # OF-423: a recall's query affect, lowered the same way onto the engine's
    # `QueryAffect`; the engine's recall door refuses it out of range.
    'query_affect': {'rust': 'Option<oneiron::task_verb::sdk::QueryAffect>', 'napi': 'Option<NapiQueryAffect>', 'native_ts': 'QueryAffect | undefined', 'py': 'dict[str, Any] | None', 'stub': 'QueryAffect | None', 'native_py': 'Option<&str>', 'json': True,
        'napi_convert': 'let {name} = {name}.map(query_affect_to_engine);', 'py_convert': 'let {name}: Option<oneiron::task_verb::sdk::QueryAffect> = {name}.map(|value| decode(value, "recall query affect")).transpose()?;', 'field': '{name}'},
    'ref': {'rust': 'Option<&str>', 'napi': 'Option<String>', 'native_ts': 'string | undefined', 'py': 'str | None', 'stub': 'str | None', 'native_py': 'Option<String>', 'borrow': '', 'suffix': '.as_deref()', 'field': '{name}.map(str::to_owned)'},
    # OF-237: the receipt kinds a read lists, as `ReceiptKind` names them; none
    # is the gate decision ledger.
    'kinds': {'rust': '&[String]', 'napi': 'Option<Vec<String>>', 'native_ts': 'string[] | undefined', 'py': 'list[str] | None', 'stub': 'list[str] | None', 'native_py': 'Option<Vec<String>>',
        'napi_convert': 'let {name} = {name}.unwrap_or_default();', 'py_convert': 'let {name} = {name}.unwrap_or_default();', 'borrow': '&', 'field': 'Some({name}.to_vec())'},
    'json': {'napi': 'String', 'native_ts': 'string', 'py': 'dict[str, Any]', 'native_py': '&str', 'json': True},
}
RESULTS = {
    'WitnessReceipt': ('NapiWitnessReceipt', 'witness_receipt_from_engine', None),
    'CommitReceipt': ('NapiCommitReceipt', 'commit_receipt_from_engine', None),
    'MemoryPack': ('NapiMemoryPack', 'memory_pack_from_engine', 'boundary_error'),
    'MemoryReceipt': ('NapiGateReceipt', 'gate_receipt_from_engine', 'boundary_error'),
}

def native_binding(row):
    'The binding the native layer types, or None when it is the generic agent-verb door.'
    binding = row.get('binding')
    return None if binding and binding.get('native') == 'agent_verb' else binding

def js_method(name):
    parts = name.replace('.', '_').split('_')
    return parts[0] + ''.join(part.title() for part in parts[1:])

def container_type(value):
    for container in ['Option', 'Vec']:
        if value.startswith(container + '<') and value.endswith('>'):
            return container, value[len(container) + 1:-1]
    return None, value.rsplit('::', 1)[-1]

def boundary_type(value, language, wire=False):
    container, inner = container_type(value)
    if container:
        item = boundary_type(inner, language, wire)
        if language == 'napi': return container + '<' + item + '>'
        if container == 'Option': return item + (' | None' if language.startswith('py') else ' | null')
        return f'list[{item}]' if language.startswith('py') else f'({item})[]' if ' | ' in item else item + '[]'
    if language == 'napi': return RESULTS[inner][0]
    if language == 'py': return {'String': 'str', 'bool': 'bool'}.get(inner, 'dict[str, Any]')
    # A type the package declares by hand is the shape its native conversion
    # returns; any other is the generated wire declaration.
    if language == 'py_stub':
        name = {'String': 'str', 'bool': 'bool', 'MemoryReceipt': 'FacadeReceipt', 'MemoryExport': 'dict[str, Any]'}.get(inner, inner)
        return name if name in ('str', 'bool', 'dict[str, Any]') or name in hand_declared('py') else INVENTORY.py_type(value)
    name = {'String': 'string', 'bool': 'boolean', 'MemoryReceipt': 'FacadeReceipt', **({'KeyValueItem': 'WireItem'} if wire else {})}.get(inner, inner)
    return name if name in ('string', 'boolean') or name in hand_declared('ts') else INVENTORY.ts_type(value)

@functools.cache
def hand_declared(language):
    'The type names a package declares by hand: its TypeScript type modules and agent-verbs template, or the stub\'s top level.'
    if language == 'ts':
        text = (ROOT/'packages/oneiron/src/types.ts').read_text() + (ROOT/'packages/oneiron/src/key-value.ts').read_text() + AGENT_VERBS_TS
        return frozenset(re.findall(r'^export (?:type|interface) (\w+)', text, re.M))
    text = (ROOT/'crates/oneiron-py/python/oneiron/__init__.pyi').read_text()
    return frozenset(a or b for a, b in re.findall(r'^(?:class (\w+)\b|(\w+) = )', text, re.M))

def remote_boundary(row):
    binding = row.get('binding', {})
    args = binding.get('args')
    if args and binding.get('wire') != 'json':
        declaration = ', '.join(a['name'] + ': ' + ARGUMENTS[a['kind']]['rust'] for a in args)
        if binding.get('assemble'):
            values = [(a['name'], ARGUMENTS[a['kind']]['field'].format(name=a['name'])) for a in args]
            fields = ', '.join(name if value == name else name + ': ' + value for name, value in values)
            if row['name'] == 'describe' or binding.get('defaults'):
                fields += ', ..Default::default()'
            setup = f'let input = {rust_type(row["input"])} {{ {fields} }};'
            value = '&input'
        else:
            setup = ''
            value = args[0]['name']
    else:
        declaration = f'input: &{rust_type(row["input"])}'
        setup, value = '', 'input'
    return declaration, setup, value

def napi_result(value, expression='output'):
    container, inner = container_type(value)
    if container == 'Vec':
        return f'{expression}.into_iter().map(|item| {{ {napi_result(inner, "item")} }}).collect()'
    _, convert, error = RESULTS[inner]
    call = f'{convert}({expression})'
    return f'{call}.map_err({error})' if error else f'Ok({call})'

def native_args(row):
    binding = native_binding(row)
    return binding['args'] if binding else [{'name': 'input', 'kind': 'json'}]
def native_boundary(row, language):
    method = row['name'].replace('.', '_')
    binding = native_binding(row)
    args = native_args(row)
    typed = binding is not None and binding.get('wire') != 'json'
    names = {a['name']: a['name'] + ('_json' if ARGUMENTS[a['kind']].get('json') and (language == 'py' or not typed) else '') for a in args}
    if language == 'napi':
        if not binding:
            # FIX 2884: a JS number reads as the typed decode behind it does
            # (`js_json` in client.rs: safe whole numbers back to integers).
            return f'#[napi] pub fn {method}(&self, input: serde_json::Value) -> napi::Result<serde_json::Value> {{ self.inner.agent_verb("{row["name"]}", js_json(input)).map_err(facade_error) }}'
        declaration = ', '.join(names[a['name']] + ': ' + ARGUMENTS[a['kind']]['napi'] for a in args)
        output = boundary_type(row['output'], 'napi') if typed else 'String'
        head = f'#[napi] pub fn {method}(&self, {declaration}) -> napi::Result<{output}> {{'
    else:
        declaration = ', '.join(names[a['name']] + ': ' + ARGUMENTS[a['kind']]['native_py'] for a in args)
        signature = ', '.join(names[a['name']] + ('=None' if ARGUMENTS[a['kind']]['native_py'].startswith('Option<') else '') for a in args)
        annotation = f'#[pyo3(signature = ({signature}))]' if '=None' in signature else ''
        # Clippy caps a function at seven parameters: a long verb takes its
        # receiver as a PyRef and its GIL token from it.
        receiver = "slf: PyRef<'_, Self>" if len(args) > 5 else "&self, py: Python<'_>"
        params = len(args) + (1 if len(args) > 5 else 2)
        head = f"{annotation} {long_signature(params)}fn {method}({receiver}, {declaration}) -> PyResult<String> {{"
    if typed:
        setup = '\n'.join(ARGUMENTS[a['kind']].get(language + '_convert', '').format(name=names[a['name']], default=json.dumps(a.get('default'))) for a in args)
        arguments = ', '.join(ARGUMENTS[a['kind']].get('borrow', '') + names[a['name']] + ARGUMENTS[a['kind']].get('suffix', '') for a in args)
        call = f'self.inner.{method}({arguments})'
    else:
        name = names[args[0]['name']]
        if language == 'napi':
            setup = f'let input: serde_json::Value = serde_json::from_str(&{name}).map_err(|error| facade_error(oneiron::memory::MemoryError {{ code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(), message: format!("invalid keyed request: {{error}}"), suggestions: vec!["Use the documented keyed DTO.".to_owned()], successor_short_id: None, gate_denial: None, read_receipt: None, policy_denial: None, wrong_root: None, hook: None, retry_after: None, resets_at: Vec::new() }}))?;'
        else:
            setup = f'let input: serde_json::Value = decode({name}, "{row["name"]}")?;'
        call = f'self.inner.agent_verb("{row["name"]}", input)'
    if language == 'napi':
        tail = napi_result(row['output']) if typed else 'serde_json::to_string(&output).map_err(|error| boundary_error(error.to_string()))'
        body = f'{setup} let output = {call}.map_err(facade_error)?; {tail}'
    else:
        encode_output = 'encode_recall(&output)' if row['name'] == 'vault.recall' else 'encode(&output)'
        if len(args) > 5:
            setup += ' let inner = &slf.inner; let py = slf.py();'
            call = call.replace('self.inner.', 'inner.', 1)
        body = f'{setup} let output = py.detach(|| {call}).map_err(raise)?; {encode_output}'
    return head + body + '}\n'

def ts_wire_type(row):
    fields = row['binding'].get('output_fields')
    if fields:
        return '{' + '; '.join(name + ': ' + boundary_type(kind, 'ts', True) for name, kind in fields.items()) + '}'
    return boundary_type(row['output'], 'ts', True)

def ts_from_wire(kind, value):
    container, inner = container_type(kind)
    if container == 'Option': return f'{value} === null ? null : ' + ts_from_wire(inner, value)
    if container == 'Vec' and inner != 'String': return f'{value}.map(item => ' + ts_from_wire(inner, 'item') + ')'
    return f'itemFromWire({value})' if inner == 'KeyValueItem' else value

def ts_doc(row):
    'A row\'s description as the JSDoc of each TypeScript method that calls it.'
    return f'/** {row["description"]} */' if row.get('description') else ''

def ts_input(row):
    'A whole-input parameter: its generated type, defaulted when the input names nothing.'
    return 'input: ' + INVENTORY.ts_type(row['input']) + (' = {}' if row['input'] == 'EmptyRequest' else '')

def ts_facade(row):
    binding = row['binding']; method = js_method(row['name'])
    if binding.get('request'):
        output_type = INVENTORY.ts_type(row['output'])
        return ts_doc(row), ts_input(row), output_type, f'this.#client.{method}(input) as {output_type}'
    args = binding['args']
    output = boundary_type(row['output'], 'ts')
    declaration = []
    for a in args:
        name = js_method(a['name']); kind = a['kind']
        optional = kind != 'json' and ARGUMENTS[kind]['native_ts'].endswith(' | undefined') and 'default' not in a
        typ = boundary_type(row['input'], 'ts') if kind == 'json' else ARGUMENTS[kind]['native_ts'].replace(' | undefined', '')
        declaration.append(name + ('?' if optional else '') + ': ' + typ + (' = ' + json.dumps(a['default']) if 'default' in a else ''))
    if binding.get('options'):
        declaration = [declaration[0], 'opts: ' + binding['options'] + ' = {}']
        arguments = [args[0]['name']] + ['opts.' + js_method(a['name']) + (' ?? ' + json.dumps(a['default']) if 'default' in a else '') for a in args[1:]]
    else:
        arguments = [js_method(a['name']) for a in args]
    if binding.get('native') == 'agent_verb':
        request = '{' + ', '.join(a['name'] + ': ' + js_method(a['name']) for a in args) + '}'
        body = f'this.#client.{method}({request}) as {output}'
    elif binding.get('wire') == 'json':
        fields = binding.get('input_fields', {}); request = args[0]['name']; setup = ''
        if fields:
            defaults = binding.get('input_defaults', {})
            destructure = ', '.join(name + (' = ' + json.dumps(defaults[name]) if name in defaults else '') for name in fields)
            setup = f'const {{ {destructure}, ...rest }} = {request};'
            request = '{ ...rest, ' + ', '.join(wire + ': ' + name for name, wire in fields.items()) + ' }'
        call = f'JSON.parse(this.#client.{method}(keyedJson({request}))) as {ts_wire_type(row)}'
        fields = binding.get('output_fields')
        result = '{' + ', '.join(js_method(name) + ': ' + ts_from_wire(kind, 'result.' + name) for name, kind in fields.items()) + '}' if fields else ts_from_wire(row['output'], 'result')
        body = f'{{ {setup} const result = {call}; return {result} }}'
    else:
        body = f'this.#client.{method}(' + ', '.join(arguments) + ')'
    return binding['docs']['ts'], ', '.join(declaration), output, body

# A facade row with no typed binding takes the generic agent-verb door. Its
# handle method takes the positional parameters its generic binding spells
# (`handle_args`), or else its whole input. Every type is the generated one,
# or the package's own declaration of it.
def ts_handle_shape(row):
    'A generic-door verb\'s TypeScript parameters and the input they send.'
    if 'handle_args' not in row: return ts_input(row), 'input'
    params, fields = [], []
    for a in row['handle_args']:
        name, field, kind = js_method(a['name']), a.get('field', a['name']), a['type']
        if 'default' in a: params.append(f'{name} = {json.dumps(a["default"])}')
        elif kind.startswith('Option<'): params.append(f'{name}?: {boundary_type(kind[len("Option<"):-1], "ts")}')
        else: params.append(f'{name}: {boundary_type(kind, "ts")}')
        if field == '$': return ', '.join(params), name
        fields.append(name if field == name else f'{field}: {name}')
    return ', '.join(params), '{' + ', '.join(fields) + '}'

def py_handle_shape(row):
    'A generic-door verb\'s Python parameters, those parameters as the stub types them, and the input they send.'
    if 'handle_args' not in row:
        empty = row['input'] == 'EmptyRequest'
        return ('spec=None' if empty else 'spec', f'spec: {INVENTORY.py_type(row["input"])}' + (' | None = None' if empty else ''),
                '{} if spec is None else spec' if empty else 'spec')
    params, typed, fields = [], [], []
    for a in row['handle_args']:
        name, field, kind = a['name'], a.get('field', a['name']), a['type']
        default = json.dumps(a['default']) if 'default' in a else 'None' if kind.startswith('Option<') else None
        params.append(name + (f'={default}' if default else ''))
        typed.append(f'{name}: {INVENTORY.py_type(kind)}' + (f' = {default}' if default else ''))
        if field == '$': return ', '.join(params), ', '.join(typed), name
        fields.append(f'{json.dumps(field)}: {name}')
    return ', '.join(params), ', '.join(typed), '{' + ', '.join(fields) + '}'

def ts_handle_verb(row):
    'A facade verb on the generic door: its doc, parameters, result type and body.'
    method = js_method(row['name'])
    if row['name'] == 'ask':
        params = ('...args: [spec: TaskAskSpec] | [who: TaskAskWho | undefined, what: TaskAskQuestion, '
                  'until?: number | null, defaultBranch?: TaskAskDefault]')
        body = ('{ const input: TaskAskSpec | TaskAskShort = args.length === 1 ? args[0] : '
                '{who: typeof args[0] === "string" ? {people: [args[0]]} : Array.isArray(args[0]) ? {people: args[0]} : args[0], what: args[1], until: args[2], default: args[3]}; '
                f'return this.#client.{method}(input) as TaskAskReceipt }}')
        return ts_doc(row), params, 'TaskAskReceipt', body
    params, value = ts_handle_shape(row)
    output = INVENTORY.ts_type(row['output'])
    return ts_doc(row), params, output, f'this.#client.{method}({value}) as {output}'

def verb_tree(rows):
    'The rows as their path tree: a segment can name a verb and hold verbs at once.'
    tree = {}
    for row in rows:
        node, parts = tree, row['name'].split('.')
        for part in parts[:-1]:
            node = node.setdefault(part, {'row': None, 'children': {}})['children']
        node.setdefault(parts[-1], {'row': None, 'children': {}})['row'] = row
    return tree

def ts_verb(row):
    return ts_facade(row) if 'binding' in row else ts_handle_verb(row)

def ts_members(tree, depth):
    'One object literal per namespace: an arrow per verb, a nested literal per child namespace.'
    pad, out = '  ' * depth, ''
    for name, node in tree.items():
        inner = ts_members(node['children'], depth + 1)
        if node['row']:
            doc, params, output, body = ts_verb(node['row'])
            value = f'({params}): {output} => this.#call(() => {body})'
            if node['children']: value = f'Object.assign({value}, {{\n{inner}{pad}}})'
            out += (pad + doc + '\n' if doc else '') + f'{pad}{name}: {value},\n'
        else:
            out += f'{pad}{name}: {{\n{inner}{pad}}},\n'
    return out

def ts_class_verbs(tree):
    'The facade class body: a bare verb is a method, a root a readonly namespace.'
    out = ''
    for name, node in tree.items():
        members = ts_members(node['children'], 2)
        if node['row'] and not node['children']:
            doc, params, output, body = ts_verb(node['row'])
            out += ('  ' + doc + '\n' if doc else '') + f'  {name}({params}): {output} {{ return this.#call(() => {body}) }}\n'
        elif node['row']:
            doc, params, output, body = ts_verb(node['row'])
            out += ('  ' + doc + '\n' if doc else '') + f'  readonly {name} = Object.assign(({params}): {output} => this.#call(() => {body}), {{\n{members}  }})\n'
        else:
            out += f'  readonly {name} = {{\n{members}  }}\n'
    return out

def py_doc(row):
    'A row\'s description as the docstring of each Python method that calls it.'
    return f'        """{row["description"]}"""\n' if row.get('description') else ''

def python_facade(row, stub=False, method_name=None):
    binding = row['binding']
    if binding.get('request'):
        if stub:
            signature = f'    def {method_name or leaf(row["name"])}(self, input: {INVENTORY.py_type(row["input"])}) -> {INVENTORY.py_type(row["output"])}:'
            return signature + ('\n' + py_doc(row) if py_doc(row) else ' ...\n')
        signature = f'    def {method_name or leaf(row["name"])}(self, input: dict[str, Any]) -> Any:'
        method = row['name'].replace('.', '_')
        return signature + '\n' + py_doc(row) + f'        return json.loads(_translate(lambda: self._client.{method}(json.dumps(input, allow_nan=False))))\n'
    args = binding['args']
    declaration = ['self']; values = []
    for n, a in enumerate(args):
        info = ARGUMENTS[a['kind']]; name = a['name']
        if n == 1 and binding.get('options'): declaration.append('*')
        typ = boundary_type(row['input'], 'py_stub') if stub and a['kind'] == 'json' else info.get('stub' if stub else 'py')
        default = repr(a['default']) if 'default' in a else 'None' if info['native_py'].startswith('Option<') else None
        declaration.append(name + ': ' + typ + (' = ' + default if default is not None else ''))
        value = 'json.dumps(' + name + (', allow_nan=False' if binding.get('wire') == 'json' else '') + ')' if info.get('json') else name
        if info.get('json') and default == 'None': value += ' if ' + name + ' is not None else None'
        values.append(value)
    if binding.get('native') == 'agent_verb':
        values = ['json.dumps({' + ', '.join(json.dumps(a['name']) + ': ' + a['name'] for a in args) + '})']
    output = boundary_type(row['output'], 'py_stub' if stub else 'py')
    signature = f'    def {method_name or leaf(row["name"])}(' + ', '.join(declaration) + f') -> {output}:'
    if stub: return signature + ' ...\n'
    return signature + '\n        """' + binding['docs']['py'] + '"""\n        return json.loads(_translate(lambda: self._client.' + row['name'].replace('.', '_') + '(' + ', '.join(values) + ')))\n'

def leaf(name):
    'The Python method a row ends in; a keyword (`continue`) takes the trailing underscore PEP 8 gives it.'
    part = name.rsplit('.', 1)[-1]
    return part + '_' if keyword.iskeyword(part) else part

def python_handle_verb(row, stub=False, name=None):
    'A facade verb on the generic door, as a method of its namespace.'
    name, method = name or leaf(row['name']), row['name'].replace('.', '_')
    output = INVENTORY.py_type(row['output'])
    if row['name'] == 'ask':
        if stub:
            return ('    @overload\n'
                    f'    def {name}(self, spec_or_who: {INVENTORY.py_type(row["input"])}) -> {output}: ...\n'
                    '    @overload\n'
                    f'    def {name}(self, spec_or_who: str | list[str] | set[str] | tuple[str, ...] | dict[str, Any] | None, '
                    f'what: dict[str, Any], until: int | None = None, default: str = "ask_me") -> {output}: ...\n')
        return (f'    def {name}(self, spec_or_who, what=None, until=None, default="ask_me"):\n' + py_doc(row) +
                '        if what is None:\n'
                '            input = spec_or_who\n'
                '        else:\n'
                '            who = {"people": [spec_or_who]} if isinstance(spec_or_who, str) else {"people": list(spec_or_who)} if isinstance(spec_or_who, (set, list, tuple)) else spec_or_who\n'
                '            input = {"who": who, "what": what, "until": until, "default": default}\n'
                f'        return json.loads(_translate(lambda: self._client.{method}(json.dumps(input))))\n')
    params, typed, value = py_handle_shape(row)
    if stub: return f'    def {name}(self' + (', ' + typed if typed else '') + f') -> {output}:' + ('\n' + py_doc(row) if py_doc(row) else ' ...\n')
    return f'    def {name}(self' + (', ' + params if params else '') + '):\n' + py_doc(row) + f'        return json.loads(_translate(lambda: self._client.{method}(json.dumps({value}))))\n'

def python_verb(row, stub=False, name=None):
    return python_facade(row, stub, name) if 'binding' in row else python_handle_verb(row, stub, name)

def python_namespace_class(path):
    return '_' + ''.join(part.title() for part in '_'.join(path).split('_')) + 'Verbs'

def python_class_verbs(tree, stub=False):
    'The facade class body: a bare verb is a method, a namespace a property whose class nests in it.'
    members, classes = '', ''
    def accessor(name, path):
        cls = python_namespace_class(path)
        body = ' ...' if stub else f'\n        return Oneiron.{cls}(self._client)'
        return f'    @property\n    def {name}(self) -> "Oneiron.{cls}":{body}\n'
    def namespace(path, node):
        nonlocal classes
        body = '' if stub else '    def __init__(self, client: _NativeClient) -> None:\n        self._client = client\n'
        if node['row']: body += python_verb(node['row'], stub, '__call__')
        nested = [(name, child) for name, child in node['children'].items() if child['children'] or not child['row']]
        for name, child in node['children'].items():
            body += accessor(name, path + [name]) if (name, child) in nested else python_verb(child['row'], stub)
        classes += f'class {python_namespace_class(path)}:\n' + (body or '    ...\n')
        for name, child in nested: namespace(path + [name], child)
    for name, node in tree.items():
        if node['row'] and not node['children']: members += python_verb(node['row'], stub)
        else:
            members += accessor(name, [name]); namespace([name], node)
    return members + ''.join('    ' + line + '\n' if line else '\n' for line in classes.splitlines())

def ts_native_signature(row):
    binding = native_binding(row); method = js_method(row['name'])
    if not binding: return f'{method}(input: unknown): unknown'
    output = 'string' if binding.get('wire') == 'json' else boundary_type(row['output'], 'ts')
    args = ', '.join(a['name'] + ('Json' if binding.get('wire') == 'json' else '') + ': ' + ARGUMENTS[a['kind']]['native_ts'] for a in binding['args'])
    return f'{method}({args}): {output}'

# `McpVerbArguments` names one field differently from its wire key.
MCP_ARGUMENT_FIELDS = {'self': 'self_target'}

def mcp_input_projection(row):
    'One row of the tools/call projection: its arguments assembled into the typed input.'
    fields = row['mcp_fields']
    required = row.get('mcp_required_fields', fields)
    root = [field for field, path in fields.items() if path == '$']
    others = [(field, path) for field, path in fields.items() if path != '$']
    if not others:
        head = f'a.{root[0]}.clone().ok_or_else(invalid)' if root else 'Ok(Value::Object(serde_json::Map::new()))'
        return f'{json.dumps(row["name"])} => {head},\n'
    if root:
        lines = [f'let mut input = a.{root[0]}.clone().ok_or_else(invalid)?;', 'let map = input.as_object_mut().ok_or_else(invalid)?;']
    else:
        lines = ['let mut map = serde_json::Map::new();']
    equalities = []
    for field, path in others:
        member = 'a.' + MCP_ARGUMENT_FIELDS.get(field, field)
        if path.startswith('='):
            # A redundant envelope field must name what the input names.
            equalities.append(f'if {member}.as_deref() != map.get({json.dumps(path[1:])}).and_then(Value::as_str) {{ return Err(invalid()); }}')
        elif field in required:
            lines.append(f'map.insert({json.dumps(path)}.to_owned(), json!({member}.as_ref().ok_or_else(invalid)?));')
        else:
            lines.append(f'if let Some(value) = &{member} {{ map.insert({json.dumps(path)}.to_owned(), json!(value)); }}')
    lines += equalities
    lines.append('Ok(input)' if root else 'Ok(Value::Object(map))')
    return f'{json.dumps(row["name"])} => {{\n' + '\n'.join(lines) + '\n},\n'

def mcp_argument_projection(row):
    'The inverse: the tools/call arguments one code-mode input projects onto.'
    lines = []
    for field, path in row['mcp_fields'].items():
        if path == '$':
            lines.append(f'arguments.insert({json.dumps(field)}.to_owned(), input.clone());')
        else:
            lines.append(f'if let Some(value) = input.get({json.dumps(path.removeprefix("="))}) {{ arguments.insert({json.dumps(field)}.to_owned(), value.clone()); }}')
    return f'{json.dumps(row["name"])} => {{\n' + '\n'.join(lines) + '\n},\n'

# OF-533 (FIX 2762): `task_decisions` marks a task row that may ask the host's
# decision ladder: a post's take question, a report's done and ask-up
# questions. A model rung may block on the server's runtime, so MCP and the
# facade run these rows on a blocking thread, on a credential surface built
# there with the ladder bound. The flag is the one source: the emitters pick
# the worker from it, and the facade binds the ladder by the catalog's
# `takes_task_decisions`, read from it too. Absent is false.
def takes_task_decisions(row):
    'Whether the served doors run this row on a worker with the ladder bound.'
    return bool(row.get('task_decisions'))

# Rule 5 (FIX 2166): plain memory rows whose engine call is a task-work producer
# the engine queues in the vault's task-work line, though the row is not
# classified task work: a highway accept, a project tradeoff's routing, an
# office fork's merge and a proposal's settlement. The server's dispatch and
# its MCP dispatch await their turn as for a task-work row and bind it, so the
# engine never waits for one on the server's runtime.
TASK_PRODUCER_ROWS = ('tasks.accept', 'vault.projects.route_tradeoff',
                      'vault.artifacts.body.fork.merge', 'vault.artifacts.body.proposal.settle')
# Rule 5 (FIX 2166): plain memory rows one branch of whose engine call is a
# task-work producer, each keyed to the predicate over the request that says
# it takes that branch: describe(handle/after) answers a highway handle's
# status, whose entry admits. The served dispatch and its MCP dispatch ask it
# of the args the pre hooks left (FIX 4445), then await a turn for such a
# request and bind it, as for a producer row.
TASK_PRODUCER_BRANCHES = {'describe': 'oneiron::task_verb::sdk::describe_takes_task_work_turn'}

def task_producer_branch_turns(args):
    'The MCP turn test for each producer branch, over the args its pre hooks left.'
    return ' || '.join(f'(tool == {json.dumps(name)} && {predicate}(&{args}))'
                       for name, predicate in TASK_PRODUCER_BRANCHES.items()) or 'false'

def takes_task_work_turn(row):
    'Whether the served doors await a task-work turn for this row and bind it.'
    if row['name'] not in TASK_PRODUCER_ROWS:
        return bool(row.get('task_work'))
    if (row.get('host_door') or row.get('server_door') or row.get('context', 'memory') != 'memory'
            or row.get('admission', {}).get('born_record_scope') or 'rows' in row.get('admission', {}).get('readable', [])
            or takes_task_decisions(row)):
        raise ValueError(f'{row["name"]}: a task-work producer row is a plain memory row')
    return True

def mcp_input_dispatch(row):
    'One row of the input dispatcher every MCP door shares.'
    name, method = row['name'], row['name'].replace('.', '_')
    decode = f'let input: {rust_type(row["input"])} = serde_json::from_value(input).map_err(|_| invalid())?;\n'
    if row.get('context') == 'board':
        return f'{json.dumps(name)} => {{\n{decode}execute_mcp_board_verb(server, actor, served, board_hooks, |context| oneiron::task_verb::sdk::{method}(context, input)).await }},\n'
    body = ''
    if name == 'describe':
        # One target per describe (FIX 3256), on the args the pre hooks left,
        # before the self, card-key and TASKS-section paths.
        body += f'oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &input).map_err(mcp_facade_error)?;\n'
        # describe(self) renders the authenticated run brief, the same door REST takes.
        body += ('if input.get("self").and_then(Value::as_bool) == Some(true) {\n'
                 '    let auth = actor.auth.as_ref().ok_or_else(invalid)?;\n'
                 '    let (value, listed) = crate::api::context_board::describe_self_for_auth(server, auth, &input).await.map_err(|_| invalid())?;\n'
                 '    // Derived from the rows its card lists, the roster it read among them.\n'
                 '    served.extend(listed);\n'
                 '    let output: oneiron::task_verb::TaskDescription = serde_json::from_value(value).map_err(|_| invalid())?;\n'
                 '    let (value, source) = mcp_describe_result(output)?;\n'
                 '    return Ok((value, source, McpCarrierPolicy::Drain, None));\n'
                 '}\n')
    admission = row.get('admission', {})
    if admission.get('owner_grade'):
        # A full-vault result needs verifier-produced owner proof, as on REST.
        body += ('let auth = actor.auth.as_ref().ok_or_else(invalid)?;\n'
                 'if !auth.is_owner_grade() { return Err(McpGatewayError::new(-32020, "forbidden", "full-vault export requires owner authority")); }\n'
                 f'oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &input).map_err(mcp_facade_error)?;\n' + decode +
                 '// A host credential resolves first (FIX 2222): a hosted operator root gets the typed refusal, and a self-hosted root or the explicit dev mode exports as the owner it acts as.\n'
                 'let action = crate::api::host_action::host_action_of(server.vault(), auth).transpose().map_err(|error| mcp_engine_error("host action failed", error))?;\n'
                 '// The person path lists through its surface; the host paths beside their archive. A slip keeps its own path; a host action with no slip (the dev mode) takes the host-action export.\n'
                 '// Each arm records the owner act with where he spoke from: an MCP row carries no request headers (FIX 4625, 4626).\n'
                 'let surface = crate::api::facade::owner_binding::act_surface(auth);\n'
                 'let output = match (auth.verified_slip(), action) {\n'
                 '    (Some(proof), _) if proof.claims().holder_ref == "host" => server.vault.export_with_verified_host_owner_listing(&input, proof, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output }),\n'
                 '    (Some(proof), _) => memory.export_with_verified_owner(&input, proof, surface),\n'
                 '    (None, Some(action)) => server.vault.export_with_host_action_listing(&input, &action, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output }),\n'
                 '    // A managed vault\'s attested owner carries no slip: the request\'s own owner proof, which the export revalidates in its snapshot, as the facade takes it (FIX 5202).\n'
                 '    (None, None) if auth.managed_owner().is_some() => {\n'
                 '        let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| McpGatewayError::new(-32020, "forbidden", "full-vault export requires verified owner authority"))?;\n'
                 '        server.vault.export_with_authenticated_owner_listing(&input, &owner, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output })\n'
                 '    }\n'
                 '    (None, None) => return Err(McpGatewayError::new(-32020, "forbidden", "full-vault export requires verified owner authority")),\n'
                 '}.map_err(mcp_facade_error)?;\n')
    elif row.get('host_door'):
        # A host door answers from the server's own state, under the same
        # credential the REST facade passes it.
        session_arg = 'actor.off_record_session.as_deref().map(oneiron::EntityId::from_hex).transpose().map_err(|_| invalid())?, ' if row.get('host_door_session') else ''
        lens_arg = 'owner, ' if row.get('host_door_lens_owner') else ''
        surface_arg = 'crate::api::facade::owner_binding::act_surface(auth), ' if row.get('host_door_surface') else ''
        # A caller door keeps the invocation its call hands it in its own rows:
        # a call that keeps no record hands its hidden id (FIX 5381).
        caller_arg = f'(actor.actor_ref, actor.actor_class), oneiron::task_verb::verb_hook_boundary::door_invocation_of(&memory, {json.dumps(name)}), '
        door = f'crate::api::facade::host_doors::{method}(server, auth, {session_arg}{caller_arg if row.get("host_door_caller") else ""}{lens_arg}{surface_arg}input).await'
        # The card's owner names the request as the row runs it, before it decodes.
        lens_owner = f'let owner = surface.lens_owner({json.dumps(name)}, &input);\n' if row.get('host_door_lens_owner') else ''
        body += ('let auth = actor.auth.as_ref().ok_or_else(invalid)?;\n'
                 f'oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &input).map_err(mcp_facade_error)?;\n' + lens_owner + decode +
                 (f'let (output, listed) = {door};\n'
                  '// Derived from the rows its reads listed: unknown when its path lists none (FIX 5988).\n'
                  'served.listed(crate::api::facade::host_doors::ListedRows::rows(listed));\n'
                  'let output = output.map_err(mcp_facade_error)?;\n' if row.get('host_door_lists') else
                  f'let output = {door}.map_err(mcp_facade_error)?;\n'))
    elif row.get('server_door'):
        # A server door runs the verb with the host's execution inputs, as on REST.
        home_door = HOME_SERVER_DOORS.get(name)
        door_call = (f'{home_door}(actor.actor_ref, actor.actor_class, proof, actor.destination(), None, input, actor.home_caller())'
                     if home_door else f'{row["server_door"]}_listing(actor.actor_ref, actor.actor_class, proof, actor.locality(), None, input)')
        body += (f'oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &input).map_err(mcp_facade_error)?;\n' + decode +
                 'let proof = actor.auth.as_ref().and_then(crate::auth::CoreAuth::verified_slip).cloned();\n'
                 f'let (output, listed) = server.{door_call}.await;\n'
                 '// Derived from these rows too, though it names none of them.\n'
                 'served.extend(listed);\n'
                 'let output = output.map_err(mcp_facade_error)?;\n')
    else:
        body += decode
        if name == 'describe':
            # describe(card key) expands a board card, under the board's own
            # scope and frame-epoch checks.
            body += ('if let Some(key) = input.key.clone() {\n'
                     '    let frame_epoch = input.frame_epoch;\n'
                     '    return execute_mcp_board_verb(server, actor, served, board_hooks, |context| oneiron::board_verb::dispatch_board_verb(context, oneiron::board_verb::BoardVerbCall::Expand { key, frame_epoch })).await;\n'
                     '}\n')
            # The TASKS section reaches MCP as rows, narrowed to the credential before its render cap.
            body += ('if input.task_ref.is_none() && input.handle.is_none() && input.after.is_none() && !input.self_target && !input.vault {\n'
                     '    // The section is narrowed to this credential before its\n'
                     "    // render cap, so its counts are the credential's rows alone.\n"
                     '    let rows = memory.describe_rows().map_err(mcp_facade_error)?;\n'
                     '    let (value, source) = mcp_tasks_section(server, actor, rows, served)?;\n'
                     '    return Ok((value, source, McpCarrierPolicy::Drain, None));\n'
                     '}\n')
        if 'mcp_served' in row:
            # The rows the verb reads by name: a continuation of its result is released only while they may leave.
            body += f'served.extend({row["mcp_served"]});\n'
        if takes_task_decisions(row):
            # Its hooks stay here; the typed row alone crosses to the worker.
            body += (f'let (output, listed) = mcp_task_row(server, tool, actor, surface, move |memory| oneiron::task_verb::sdk::{method}(memory, input)).await?;\n'
                     '// Derived from the rows its reads listed, on a refusal too.\n'
                     'served.extend(listed);\n'
                     'let output = output.map_err(mcp_facade_error)?;\n')
        elif name in CALL_HOME_DOORS:
            # Its page as the plain arm reads it, then the home's references.
            body += ('let asked = (input.query.clone(), input.limit);\n'
                     f'let output = oneiron::task_verb::sdk::{method}(&memory, input).map_err(mcp_facade_error)?;\n'
                     f'let (output, listed) = {CALL_HOME_DOORS[name][1]}(server.vault(), output, &asked.0, asked.1, &actor.home_caller()).await;\n'
                     '// The home\'s references, found under the caller\'s own proof.\n'
                     'served.extend(listed);\n')
        else:
            body += f'let output = oneiron::task_verb::sdk::{method}(&memory, input).map_err(mcp_facade_error)?;\n'
        if 'mcp_served_output' in row:
            body += f'served.extend({row["mcp_served_output"]});\n'
    if row.get('lands_turn'):
        body += 'server.ai.turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);\n'
    if 'mcp_result' in row:
        body += f'let (value, source) = {row["mcp_result"]}; Ok((value, source, McpCarrierPolicy::Drain, None))'
        return f'{json.dumps(name)} => {{\n{body} }},\n'
    if 'page' in row:
        # The engine's own cursor ends its page: the page reached the end of
        # what it read, and a set cursor withholds the rows past it. The MCP
        # cap counts the rows key named here, and `resume` names the argument
        # the cursor goes back as.
        page = row['page']
        source = (f'crate::mcp::McpPageSource::scoped_window(output.{page["rows"]}.len(), 0, '
                  f'usize::from(output.{page["cursor"]}.is_some()), true).rows_at({json.dumps(page["rows"])})')
        if 'resume' in page:
            assert page['resume'] in row['mcp_fields'], f'{name}: page.resume names no MCP argument'
            if 'within' in page:
                # The cursor goes back inside the argument that carries the
                # whole input, as its `within` key (FIX 9175, FIX 10186).
                assert row['mcp_fields'][page['resume']] == '$', f'{name}: page.within needs page.resume to carry the whole input'
                source += (f'.resumed_within({json.dumps(page["cursor"])}, {json.dumps(page["resume"])}, '
                           f'{json.dumps(page["within"])})')
            else:
                source += f'.resumed_by({json.dumps(page["cursor"])}, {json.dumps(page["resume"])})'
        body += f'let source = {source};\n'
    else:
        count = 'output.len()' if row['output'].startswith('Vec<') else '1'
        body += f'let source = crate::mcp::McpPageSource::complete({count});\n'
    body += 'mcp_agent_verb_output(output, source)'
    return f'{json.dumps(name)} => {{\n{body} }},\n'

def mcp_dispatch():
    invalid = 'let invalid = || McpGatewayError::new(-32602, "tool_args_invalid", "invalid typed agent-verb argument");\n'
    result = '''/// A `tools/call` of one generated verb: its arguments assemble the verb's typed
/// input, which then takes the one dispatcher every MCP door shares.
pub(super) async fn execute_mcp_agent_verb(
        server: &Arc<SyncServer>,
        args: &McpVerbToolArgs,
        actor: &McpCallContext,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
        let input = mcp_agent_verb_input(args.tool.name, &args.payload.arguments)?;
        execute_agent_verb_input(server, args.tool.name, input, actor, None, served, board_hooks).await
    }

fn mcp_agent_verb_input(tool: &str, a: &crate::mcp::McpVerbArguments) -> Result<Value, McpGatewayError> {
'''
    result += invalid + 'match tool {\n' + ''.join(mcp_input_projection(row) for row in mcp_rows()) + '_ => Err(invalid()), } }\n'
    result += '''/// The `tools/call` arguments one verb input projects onto, so a call that
/// arrives as a whole input meets the admission a tool call of that verb meets.
pub(crate) fn mcp_agent_verb_arguments(tool: &str, input: &Value) -> Result<crate::mcp::McpVerbArguments, McpGatewayError> {
'''
    result += invalid + 'let mut arguments = serde_json::Map::new();\nmatch tool {\n' + ''.join(mcp_argument_projection(row) for row in mcp_rows())
    result += '_ => return Err(invalid()), }\nserde_json::from_value(Value::Object(arguments)).map_err(|_| invalid())\n}\n'
    result += '''/// Runs one verb from its whole typed input, with the actor ceiling and
/// gate every other door applies. Every MCP door reaches the verb table here.
/// The input names only fields the verb's advertised closed schema lists, and
/// a code-mode call's claims are written under its `run`'s host origin, the
/// live lens cards it renders held for that run.
/// Every row the result was derived from is listed in `served`: those its
/// input names, and those the verb's reads picked themselves. A board read
/// leaves the hook blocks its answer shows in `board_hooks`; the caller spends
/// them once the answer is out (OF-579).
pub(crate) async fn execute_agent_verb_input(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        run: Option<McpCodeRun>,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
        let producers = oneiron::memory::ProducerRows::default();
        let produced = super::skill_execution::CALLER.scope(actor.clone(), execute_agent_verb_listing(server, tool, input, actor, run, &producers, served, board_hooks)).await;
        served.extend(producers.take());
        produced
    }

/// [`execute_agent_verb_input`], its surface listing in `producers` the rows
/// its reads pick. Every MCP and code-mode row crosses its verb hooks here,
/// once (ARCH-0080 §3), under the invocation the call carried or a fresh
/// one: the pre chain before the row, the post chain over its result.
async fn execute_agent_verb_listing(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        run: Option<McpCodeRun>,
        producers: &oneiron::memory::ProducerRows,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
'''
    result += invalid + '''if let Some(field) = crate::mcp::verb_input_unknown_field(tool, &input) {
        return Err(McpGatewayError::new(-32602, "tool_args_invalid", format!("{tool} input names unknown field `{field}`")));
    }
    if !oneiron::task_verb::sdk::AgentVerb::from_name(tool).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_mcp) {
        return Err(invalid());
    }
    // G10: MCP and code mode retain envelopes and results. Do not run a
    // memory-free turn on either, or fire a hook that could retain its text.
    if tool == "ai.anonymous_chat" {
        return Err(McpGatewayError::new(-32020, "model_unavailable",
            "anonymous chat requires its standalone HTTP SDK route"));
    }
    // A narrowed connector's TASKs are born in its own world and in the
    // facet its writes land in (its session's, or its own write facet).
    let mut position = actor.scope.birth_position();
    if let Ok(Some(facet)) = actor.landing {
        position.facet = Some(facet);
    }
    let invocation = actor.invocation.unwrap_or_else(oneiron::runtime_hooks::InvocationId::mint);
    // describe names one target (FIX 3256): a conflict is refused before its
    // hooks see it, as on REST, and again on the args they leave.
    if tool == "describe" {
        oneiron::task_verb::sdk::validate_input(tool, &input).map_err(mcp_facade_error)?;
    }
    // Rule 5: a task-work row, or a row whose engine call produces task work,
    // takes its one turn here, for MCP and code mode alike, binds it on the
    // surface its row runs on and holds it through its hooks and its row.
    let task_work_turn = if oneiron::task_verb::sdk::AgentVerb::from_name(tool).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_task_work)
        || matches!(tool, ''' + ' | '.join(json.dumps(name) for name in TASK_PRODUCER_ROWS) + ''') {
        Some(Arc::new(server.admit_task_work(actor.actor_ref).await))
    } else {
        None
    };
    let mut surface = McpRowSurface { position, invocation, run, task_work_turn: task_work_turn.clone() };
    // The direct caller's own proof, on the rows whose HTTP door binds it
    // outside a room turn (OF-417, OF-365).
    let memory = mcp_direct_authorship(server, tool, actor, surface.memory(server, actor, producers))?;
    let hooks = super::verb_hooks::mcp_row_hooks_pre(server, tool, actor, &memory, input).await?;
    // Rule 5 (FIX 4445): a row one branch of whose engine call produces task
    // work takes its turn on the args its pre hooks left, as the served
    // facade does, so a rewrite into that branch runs on an awaited turn.
    // The row holds one turn only, bound on its surface and its memory alike.
    let (memory, task_work_turn) = if task_work_turn.is_none() && (''' + task_producer_branch_turns('hooks.args') + ''') {
        let turn = Arc::new(server.admit_task_work(actor.actor_ref).await);
        surface.task_work_turn = Some(Arc::clone(&turn));
        (memory.with_task_work_turn(Arc::clone(&turn)), Some(turn))
    } else {
        (memory, task_work_turn)
    };
    let ran = execute_agent_verb_row(server, tool, hooks.args.clone(), actor, memory, surface, served, board_hooks).await;
    // A row that fails after its pre chain ran keeps a session-only call's
    // pre hook records and runs no post chain (FIX 5527).
    let (output, source, carrier, epoch) = match ran {
        Ok(ran) => ran,
        Err(error) => {
            crate::api::facade::row_hooks_abort(server, hooks).await;
            return Err(error);
        }
    };
    let output = crate::api::facade::row_hooks_post(server, hooks, output).await.map_err(mcp_facade_error)?;
    // The row's turn ends after its post hooks.
    drop(task_work_turn);
    Ok((output, source, carrier, epoch))
    }

/// One row of [`execute_agent_verb_listing`], on the args its pre chain left,
/// on `memory`, the caller's surface `surface` built. A task row that may ask
/// the host's decision ladder builds its own from `surface`, off the runtime.
async fn execute_agent_verb_row(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        memory: oneiron::Memory<'_>,
        surface: McpRowSurface,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
'''
    result += invalid + 'match tool {\n'
    result += ''.join(mcp_input_dispatch(row) for row in mcp_rows() if row['name'] != 'ai.anonymous_chat')
    result += '_ => Err(invalid()), } }\n'
    result += '''/// One typed verb result, drained in a single frame.
fn mcp_agent_verb_output(
        output: impl serde::Serialize,
        source: crate::mcp::McpPageSource,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
        let value = serde_json::to_value(output).map_err(|_| McpGatewayError::new(-32603, "engine_error", "typed agent result cannot be encoded"))?;
        Ok((value, source, McpCarrierPolicy::Drain, None))
    }
'''
    return result

def http_members(tree, depth):
    'The facade tree literal: an arrow per verb over the injected transport, a nested literal per namespace.'
    pad, out = '  ' * depth, ''
    for name, node in tree.items():
        key = name if re.fullmatch(r'[A-Za-z_$][\w$]*', name) else json.dumps(name)
        inner = http_members(node['children'], depth + 1)
        if node['row']:
            row = node['row']; verb = json.dumps(row['name'])
            value = f'({ts_input(row)}, options?: O): FacadeReturns<{verb}>[K] => invoke({verb}, input, options, newInvocation())'
            if node['children']: value = f'Object.assign({value}, {{\n{inner}{pad}}})'
            out += (pad + ts_doc(row) + '\n' if row.get('description') else '') + f'{pad}{key}: {value},\n'
        else:
            out += f'{pad}{key}: {{\n{inner}{pad}}},\n'
    return out

def http_facade():
    'OF-246: the one client artifact, the typed facade tree over an injected transport, with its row metadata; OF-580: each call\'s invocation id and the pending ask a retry resends under it.'
    out = HEADER + 'import type * as Facade from "./facade-types.js";\n\n'
    out += '/** Every facade verb, in table order. */\n'
    out += 'export const FACADE_VERBS = ' + json.dumps([r['name'] for r in FACADE_ROWS]) + ' as const;\n'
    out += 'export type FacadeVerb = typeof FACADE_VERBS[number];\n\n'
    out += '/** Each verb\'s request body, as its Rust input type reads it. */\nexport interface FacadeInputs {\n'
    out += ''.join(f'  {json.dumps(r["name"])}: {INVENTORY.ts_type(r["input"])};\n' for r in FACADE_ROWS) + '}\n'
    out += '/** Each verb\'s result: the JSON body of its 2xx response, as its Rust output type writes it. */\nexport interface FacadeResults {\n'
    out += ''.join(f'  {json.dumps(r["name"])}: {INVENTORY.ts_type(r["output"])};\n' for r in FACADE_ROWS) + '}\n'
    out += 'export type FacadeInput<V extends FacadeVerb> = FacadeInputs[V];\n'
    out += 'export type FacadeResult<V extends FacadeVerb> = FacadeResults[V];\n\n'
    out += '''/** One row of the verb table, as a client reads it. */
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
'''
    for r in FACADE_ROWS:
        out += (f'  {json.dumps(r["name"])}: {{ description: {json.dumps(r.get("description", ""))}, scope: {json.dumps(r["scope"])}, '
                f'proposes: {json.dumps(bool(r.get("proposes")))}, hostDoor: {json.dumps(bool(r.get("host_door")))}, section: {json.dumps(bool(r["section"]))} }},\n')
    out += '''};

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
  error: { code: string; message: string; requestId: string; suggestions: string[]; receiptRef?: string; hook?: FacadeHookStop; retryAfter?: number; resetsAt?: number[]; [field: string]: unknown };
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
'''
    out += http_members(verb_tree(FACADE_ROWS), 2)
    out += '''  };
}
export type FacadeTree<K extends FacadeReturn, O = RequestInit> = ReturnType<typeof facadeTree<K, O>>;

/** Retries the call `pending` names through `invoke`: its verb and input, under its own invocation id, naming the ask it stopped on. */
export function facadeRetry<K extends FacadeReturn, O, V extends FacadeVerb>(invoke: FacadeTransport<K, O>, pending: FacadePending<V>, options?: O): FacadeReturns<V>[K] {
  return invoke(pending.verb, pending.input, options, pending.invocation, pending.ask);
}
'''
    return out

# The task and ask declarations `packages/oneiron/src/agent-verbs.ts` carries.
AGENT_VERBS_TS = '''import type { RecordRef, TaskDescription as FacadeTaskDescription } from "./facade-types.js";
export interface OutcomeBinding { source: {kind: "claim" | "event"; predicate: string} | {kind: "edge"; relation: string} | {kind: "stage"; campaign: string}; horizon: number; mapping: Record<string, boolean>; noise_weight: number; linked_by?: string | null }
export interface CalibrationPair { prediction: unknown; probability: number; outcome: {answer: string; fact: string; fact_value_hash: number[]; label: boolean; noise_weight: number; occurred_at: number} }
export type TaskAssignee = "dreamer" | {agent_def: {agent_def_ref: string}} | {peer: {actor_ref: string}} | {child: {actor_ref: string}} | {human: {actor_ref: string}};
export type ConsultPayloadRef = {claim: string} | {turn: string};
export type TaskAskOptionId = string;
export type TaskAskTarget = {responder: TaskAssignee} | {people: string[]} | {authority: {class: string; selectors: string[]; target: string | null; budget: number | null; receipt_required: boolean}};
export interface TaskAskLadderPrediction { option: TaskAskOptionId; rung: "rule" | "system_one"; probability: number | null }
export interface TaskAskQuestion { reference: ConsultPayloadRef; revision: number; options: Record<TaskAskOptionId, string>; context_refs: ConsultPayloadRef[]; label?: string | null; outcome_binding?: OutcomeBinding | null; ladder_answer?: TaskAskLadderPrediction | null; class_key?: string | null }
export type TaskAskElectorate = "any" | {people: string[]};
export interface TaskAskNeed {count: number; of?: TaskAskElectorate}
export type TaskAskDecide = "first" | {all: {of: TaskAskElectorate; answer: TaskAskOptionId}} | {at_least: {count: number; of: TaskAskElectorate; answer: TaskAskOptionId}};
export type TaskAskDefault = "proceed" | "hold" | "ask_me";
export interface TaskAskDisagree {branch: "hold" | "proceed"; surface: "card" | "none"}
export interface TaskAskClass {key: string; version: number; governance: boolean; deadline_seconds: number; allowed_recipients: string[]; required_people: string[]; minimum_responses: number; required_sources: ConsultPayloadRef[]; decision: TaskAskDecide | null; disclosure: Record<string, ConsultPayloadRef[]>; fallback: TaskAskDefault[]; remind: number[]}
export type TaskAskWho = TaskAskTarget | string | string[] | null;
export interface TaskAskShort {who?: TaskAskTarget | null; what: TaskAskQuestion; until?: number | null; default?: TaskAskDefault}
export interface TaskAskSpec { intent_key: string; task_ref?: string | null; class?: TaskAskClass | null; who?: TaskAskTarget | null; what: TaskAskQuestion; until?: number | null; default?: TaskAskDefault; need?: TaskAskNeed; decide?: TaskAskDecide | null; provisional?: "inform"; on_disagree?: TaskAskDisagree; remind?: number[] | null }
export interface TaskCanAskRequest { ask: TaskAskSpec }
export interface TaskAskPreflightRecipient { who: string; face: string | null; channel: string | null; word_required: boolean }
export interface TaskAskPreflight { recipients: TaskAskPreflightRecipient[] }
export type TaskAskPersonKind = "word" | "companion" | "default" | "unknown";
export interface TaskAskPersonEvidence {who: string; answer: TaskAskWord | null; kind: TaskAskPersonKind; at: number; source: string | null}
export interface TaskAskHandle { group_ref: string }
export interface TaskAskReceipt { handle: TaskAskHandle; task_refs: string[]; hold: "NoLiveRoute" | null; idempotent_replay: boolean; task_records: RecordRef[] }
export interface TaskAskWord {result_ref: string; option?: TaskAskOptionId | null; inform_for?: string | null; provenance_refs?: ConsultPayloadRef[]}
export interface TaskAskAnswer { task_ref: string; actor_ref: string; result_ref: string; word_ref: string; task_record: RecordRef; actor_record: RecordRef; result_record: RecordRef; word_record: RecordRef }
export interface TaskAskCoverage {met: boolean; required: number; responded: string[]; unknown: string[]; unmet_people: string[]}
export type TaskAskDecision = "collected" | {first: TaskAskAnswer} | {answer: TaskAskOptionId} | "no" | "conflict" | "unknown";
export interface TaskAskFallback {branch: TaskAskDefault; surface: "card" | "none"}
export interface TaskAskEvidence {answer: TaskAskAnswer; word: TaskAskWord; source: "human" | "foreign_stated" | "inform" | "executor"; person_ref: string; order: number; reason: "counted" | "inform" | "human_dominates" | "executor" | "superseded" | "outside_electorate" | "missing_source" | "late"; ladder_changed: boolean | null}
export interface TaskAskSettlement {group_ref: string; reference: string; revision: number; at: number; cutoff_order: number; reason: "first_word" | "all_responded" | "deadline" | "stale"; requested: TaskAskSpec; effective: TaskAskSpec; base_policy_version: number; electorate: string[]; question_digest: number[]; unmet_sources: ConsultPayloadRef[]; outcome_answer_ref: string | null; link_result_proof?: number[]}
export type TaskAskEffectAuthorization = "not_evaluated_by_ask";
export interface TaskAskResult {effect_authorization: TaskAskEffectAuthorization; coverage: TaskAskCoverage; decision: TaskAskDecision; fallback: TaskAskFallback | null; evidence: TaskAskEvidence[]; settlement: TaskAskSettlement}
export type TaskAskStatus = {Pending: {hold: "NoLiveRoute" | null}} | {Changed: {voided: string[]; generation: number}} | {Settled: TaskAskResult};
export type TaskAskWait = { Pending: {trap_ref: string} } | { Changed: {voided: string[]; generation: number} } | { Ready: TaskAskResult } | {Park: {wait_id: string; effect: string; reason: string; prompt: string | null}};
export type TaskDescription = FacadeTaskDescription;
export interface TaskCancelReceipt {approval: "auto" | "proposed" | "approved" | "rejected"; effected: boolean; proposal_ref: string | null; gate_decision_ref: string | null; status: "queued" | "running" | "paused" | "completed" | "failed" | "cancelled" | "abandoned" | null; cancel_requested: boolean; forced: boolean}
'''

def run_catalog():
    'RunVerb: the rows code mode serves that the run answers itself.'
    variants = {r['name']: ''.join(part.title() for part in r['name'].replace('.', '_').split('_')) for r in RUN_ROWS}
    out = HEADER + '/// The verb-table rows a code run answers itself, as the typed `self.*` call\n'
    out += '/// each names. A row with a host projection also has a typed door bound to\n'
    out += '/// its caller\'s credential and live-run attachment.\n'
    out += '#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum RunVerb { ' + ','.join(variants.values()) + ' }\nimpl RunVerb {\n'
    out += 'pub const ALL: &[Self] = &[' + ','.join('Self::' + variant for variant in variants.values()) + '];\n'
    out += "pub fn from_name(name: &str) -> Option<Self> { Self::ALL.iter().copied().find(|verb| verb.as_str() == name) }\n"
    out += "pub const fn as_str(self) -> &'static str { match self {\n"
    out += ''.join('Self::' + variants[r['name']] + ' => ' + json.dumps(r['name']) + ',\n' for r in RUN_ROWS) + '} }\n'
    writes = ['Self::' + variants[r['name']] for r in RUN_ROWS if r['scope'] == 'Write']
    out += 'pub const fn writes(self) -> bool { matches!(self, ' + (' | '.join(writes) if writes else '_ if false') + ') }\n'
    out += 'pub const fn effect(self) -> crate::code_run::SelfEffect { match self {\n'
    out += ''.join('Self::' + variants[r['name']] + ' => crate::code_run::SelfEffect::' + r['effect'] + ',\n' for r in RUN_ROWS) + '} }\n'
    return out + '}\n'

def record_refs_check(row):
    'OF-063: the record-ref check a row with `refs` runs before its engine call.'
    if 'refs' not in row: return ''
    pointers = ', '.join(json.dumps(pointer) for pointer in row['refs'])
    check = row.get('refs_check', 'crate::gate::record_references::admit_row_references')
    return f'{check}(memory, {json.dumps(row["name"])}, &input, &[{pointers}])?; '

def prose_links_check(row):
    'OF-063 prose links: the receipt-only link read a row with `prose_links` runs before its engine call.'
    if 'prose_links' not in row: return ''
    pointers = ', '.join(json.dumps(pointer) for pointer in row['prose_links'])
    return f'let unlinked_prose = crate::gate::record_references::unlinked_prose_links(memory, {json.dumps(row["name"])}, &input, &[{pointers}])?; '

def prose_links_landed(row, call):
    """OF-063 prose links (Engine ruling 10-18): the unlinked-prose receipt
    means landed speech only, so a row with `prose_links` receipts what its
    read found only once its engine call has returned success."""
    if 'prose_links' not in row: return None
    return f'let landed = {call}; crate::gate::record_references::receipt_landed_prose(memory, &unlinked_prose); Ok(landed)'

def default_const(row, arg):
    'The engine constant that carries one binding default the manifest states.'
    return f"{row['name'].replace('.', '_')}_{arg['name']}_default".upper()

# OF-489 socket-first: one admission and one typed call per facade row, which
# every server transport runs. A transport hands the row a `FacadeCall` (the
# credential it is bound to, and what it carried beside the input) and the
# input as it decoded it, and the row reads that input where the HTTP handler
# read its body, so each refusal keeps its order. The HTTP routes all take one
# adapter (`facade_route`) over `call_verb`, and the held socket's `rpc.req`
# calls the same `call_verb`. The answer names the rows it was derived from,
# for the socket's send-time release (DEC-0005); a door that opens handles of
# its own names none, and says so. Board, browser and run rows are refused by
# the context each needs: no facade transport carries it.
DISPATCH_DOC = '''//! The facade's one admission and typed call per verb-table row (OF-489).
//! Every server transport runs a facade verb here: each HTTP route through
//! `facade_route`, the held socket's `rpc.req` through [`call_verb`]. A
//! transport hands a row its [`FacadeCall`] and the input as it decoded it;
//! the row admits the call and runs it, and its answer names the rows it was
//! derived from.
'''
DISPATCH_SIGNATURE = "server: &Arc<SyncServer>, call: &FacadeCall<'_>, input: Result<serde_json::Value, FacadeApiError>"

def facade_dispatch(facade_rows):
    'The facade routes, every one onto the shared adapter, and the dispatch both transports run.'
    # A raw door refuses any narrowed record capability; a door that reads only
    # through the credential's lane serves a facet narrowing (owner ruling
    # FACET-READ), which the lane applies row by row.
    # A door that births records lands them in the credential's landing facet,
    # which the credential must carry.
    def record_scope_guard(r):
        admission = r.get('admission', {})
        if admission.get('claim_record_scope'):
            return 'let position = facade_claim_position(server, call)?;'
        if admission.get('credential_record_scope'):
            return 'facade_scoped_credential(auth)?;'
        if admission.get('scoped_export'):
            return 'facade_scoped_export_credential(auth)?;'
        if admission.get('born_record_scope'):
            return 'let position = facade_landing(server, call)?;'
        if admission.get('lane_record_scope'):
            return 'auth.require_lane_record_scope()?;'
        # A read whose engine door filters its projection row by row through
        # the credential's own scoped read carries the credential's worlds
        # and facets (OF-250); any other narrowing, and any record or channel
        # caveat, still fails closed.
        if admission.get('projection_record_scope'):
            return ('{ let (worlds, facets) = auth.verified_slip().map_or((oneiron::federation::ScopeAxis::All, oneiron::federation::ScopeAxis::All), '
                    '|proof| (proof.scope().worlds.clone(), proof.scope().facets.clone())); '
                    'auth.require_record_scope_carried(worlds, facets)?; }')
        if admission.get('unrestricted_record_scope'):
            return 'auth.require_unrestricted_record_scope()?;'
        # Any other door reads or writes around the lane, so it refuses a facet
        # narrowing as MCP refuses a narrowed connector there.
        return 'auth.require_unnarrowed_facets()?;'
    routes = HEADER + 'use super::*;\npub(super) fn routes() -> Router<Arc<SyncServer>> { Router::new()\n'
    # G10: anonymous chat uses the existing standalone handler, never the
    # facade's invocation claim, hook chains or retained call-receipt layer.
    for r in facade_rows:
        if r['name'] == 'ai.anonymous_chat': continue
        handler = r['name'].replace('.', '_') + '_attachment' if 'attachment' in r else 'facade_route'
        routes += f'.route("/{r["name"]}", post({handler}))\n'
    routes += '}\n'
    for r in facade_rows:
        if 'attachment' not in r: continue
        handler = r['name'].replace('.', '_') + '_attachment'
        disposition = json.dumps(f'attachment; filename="{r["attachment"]}"')
        # The route's answer, encoded inside its answer scope (FIX 8238); only
        # an answer, never a refusal, is named an attachment.
        routes += f'''async fn {handler}(
            auth: CoreAuth, State(server): State<Arc<SyncServer>>, uri: axum::http::Uri,
            headers: HeaderMap, payload: Result<Json<serde_json::Value>, JsonRejection>,
        ) -> Response {{
            let mut answer = facade_route(auth, State(server), uri, headers, payload).await;
            if answer.extensions().get::<FacadeApiError>().is_none() {{
                answer.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, HeaderValue::from_static({disposition}));
            }}
            answer
        }}\n'''
    routes += 'pub(super) fn anonymous_chat_routes() -> Router<Arc<SyncServer>> { Router::new().route("/v1/core/facade/ai.anonymous_chat", post(crate::api::anonymous_chat::chat)) }\n'
    dispatch = HEADER + DISPATCH_DOC + 'use super::*;\n'
    for r in facade_rows:
        method, name = r['name'].replace('.', '_'), r['name']
        head = f"async fn {method}({DISPATCH_SIGNATURE}) -> Result<FacadeCallOutput, FacadeApiError> {{\nlet auth = call.auth();\n"
        if name == 'vault.recall': dispatch += SERVER_RECALL_DOC
        if name == 'ai.anonymous_chat':
            # Socket/RPC calls retain their envelope. Only the standalone
            # HTTP registration above can execute a traceless turn.
            dispatch += head + '''let _ = (server, auth, input);
                Err(oneiron::memory::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                    "anonymous chat requires its standalone HTTP SDK route",
                    &["Call POST /v1/ai/anonymous-chat or the HTTP SDK ai.anonymous_chat method."],
                ).into())
            }\n'''
            continue
        if r.get('admission', {}).get('owner_grade'):
            # A full-vault result must carry verifier-produced owner proof into
            # same-snapshot engine admission, never generic actor-only invoke.
            dispatch += head + f'''auth.require(CoreScope::{r["scope"]})?;
                auth.require_unrestricted_record_scope()?;
                facade_outside_room_turn(call, {json.dumps(name)})?;
                if !auth.is_owner_grade() {{
                    return Err(FacadeApiError::forbidden("full-vault export requires owner authority", ["Present a verified, unattenuated owner credential."]));
                }}
                let value = input?;
                oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &value)?;
                // A host credential resolves first (FIX 2222): a hosted
                // operator root gets the typed refusal, and a self-hosted root
                // or the explicit dev mode exports as the owner it acts as.
                let action = crate::api::host_action::facade_host_action(server, auth)?;
                let proof = auth.verified_slip();
                // A managed vault's attested owner (`ManagedOwnerAction`)
                // presents neither: the request's own owner proof, which the
                // export revalidates in its snapshot. Never the hosted root.
                let owner = match (proof, &action) {{
                    (None, None) if auth.managed_owner().is_some() => Some(super::host_doors::owner_proof(auth, server, {json.dumps(name)})?),
                    _ => None,
                }};
                if proof.is_none() && action.is_none() && owner.is_none() {{
                    return Err(FacadeApiError::forbidden("full-vault export requires verified owner authority", ["Present a verified owner credential."]));
                }}
                let hooks = facade_hooks_pre(server, call, {json.dumps(name)}, value).await?;
                // An export that fails after its pre chain ran keeps a
                // session-only call's pre hook records and runs no post chain
                // (FIX 5651), as a host door does (FIX 5527).
                let args = hooks.args.clone();
                let ran = async {{
                let input: oneiron::memory::ExportOptions = facade_input(args)?;
                // Beside the archive, the rows its snapshot read past where
                // the caller's rows go (its locality, with the machine its
                // connection proved; FIX 4937): every owner path lists them.
                // A slip keeps its own path; a host action with no slip (the
                // dev mode) takes the engine's host-action export; the
                // attested owner takes the engine's request-proof export,
                // toward its own destination. Each arm's receipt records the
                // owner's act, with where he spoke from as this request proved
                // it (audit only; FIX 4625, 4626).
                let surface = call.surface();
                let (output, rows) = match (proof, action, owner) {{
                    (Some(proof), _, _) if proof.claims().holder_ref == "host" => {{
                        server.vault.export_with_verified_host_owner_listing(&input, proof, surface, auth.destination())?
                    }}
                    (Some(proof), _, _) => {{
                        let (actor, class) = facade_actor(server, auth)?;
                        let producers = oneiron::memory::ProducerRows::default();
                        let output = server.vault.memory(actor, class).for_destination(&auth.destination()).listing_producers(&producers).export_with_verified_owner(&input, proof, surface)?;
                        (output, producers.take())
                    }}
                    (None, Some(action), _) => server.vault.export_with_host_action_listing(&input, &action, surface, auth.destination())?,
                    (None, None, Some(owner)) => {{
                        server.vault.export_with_authenticated_owner_listing(&input, &owner, surface, auth.destination())?
                    }}
                    (None, None, None) => {{
                        return Err(FacadeApiError::forbidden("full-vault export requires verified owner authority", ["Present a verified owner credential."]));
                    }}
                }};
                let output = serde_json::to_value(output).map_err(|_| FacadeApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR, MEMORY_CODE_INTERNAL,
                    "export result encoding failed", ["Report this SDK response mismatch."]
                ))?;
                Ok::<_, FacadeApiError>((output, rows))
                }}.await;
                let (output, rows) = match ran {{ Ok(ran) => ran, Err(error) => {{ row_hooks_abort(server, hooks).await; return Err(error); }} }};
                Ok(FacadeCallOutput {{ value: facade_hooks_post(server, hooks, output).await?, rows: Some(rows) }})
            }}\n'''
            continue
        if r.get('host_door'):
            # A host door answers from the server's own state, outside any
            # room turn, under the credential the call presented. It opens its
            # own handles, so no list here names the rows it read, unless the
            # door lists them itself (`host_door_lists`). A flagged one wakes
            # the turn producer after it, as its MCP arm does.
            # A restrictive call's args that do not decode as the door's typed
            # input give way to the caller's own (`facade_door_input`, FIX 5076).
            lands = r.get('lands_turn')
            landed = " server.ai.turn_landed_by(server.vault(), landed_by.0, landed_by.1);" if lands else ""
            session_arg = 'call.session()?, ' if r.get('host_door_session') else ''
            lens_arg = 'call.lens_owner(), ' if r.get('host_door_lens_owner') else ''
            surface_arg = 'call.surface(), ' if r.get('host_door_surface') else ''
            # A caller door keeps the invocation its call hands it in its own
            # rows: a call that keeps no record hands its hidden id (FIX 5381).
            caller_arg = 'caller, Some(oneiron::task_verb::verb_hook_boundary::door_invocation(&server.vault, &hooks)), '
            door = f'super::host_doors::{method}(server, auth, {session_arg}{caller_arg if r.get("host_door_caller") else ""}{lens_arg}{surface_arg}facade_door_input(&mut hooks)?).await'
            # A door that fails after the pre chain ran (the door itself, its
            # input's decode or its answer's encoding) keeps a session-only
            # call's pre hook records and runs no post chain (FIX 5527).
            failed = 'Err(error) => { row_hooks_abort(server, hooks).await; return Err(error); }'
            # FIX 10425: a browser batch's or library run's answer counts the
            # decisions its hooks' verdicts answered among its own, as its
            # code-mode door does, so `model_free` reads them. Record only.
            counted = name in HOOK_DECISION_ROWS
            pre_hooks = (f'let (mut hooks, decided) = facade_hooks_pre_counted(server, call, {json.dumps(name)}, value).await?;' if counted
                         else f'let mut hooks = facade_hooks_pre(server, call, {json.dumps(name)}, value).await?;')
            post_hooks = (f'facade_hooks_post_counted(server, hooks, {json.dumps(name)}, output, decided)' if counted
                          else 'facade_hooks_post(server, hooks, output)')
            answer = (f'''let ran = async {{
                    let (output, listed) = {door};
                    Ok::<_, FacadeApiError>((facade_output(output?)?, listed))
                }}.await;
                let (output, listed) = match ran {{ Ok(ran) => ran, {failed} }};{landed}
                Ok(FacadeCallOutput {{ value: {post_hooks}.await?, rows: super::host_doors::ListedRows::rows(listed) }})''' if r.get('host_door_lists') else
                      f'''let ran = async {{ Ok::<_, FacadeApiError>(facade_output({door}?)?) }}.await;
                let output = match ran {{ Ok(output) => output, {failed} }};{landed}
                Ok(FacadeCallOutput::unlisted({post_hooks}.await?))''')
            scope_guard = ("auth.require_granted(CoreScope::Write).or_else(|_| auth.require_granted(CoreScope::Propose))?;"
                           if r.get('proposes') and r.get('admission', {}).get('credential_record_scope')
                           # FIX 6867: a lane door judges its records in its engine door.
                           else f'auth.require_granted(CoreScope::{r["scope"]})?;'
                           if r.get('admission', {}).get('require_granted_scope')
                           else f'auth.require(CoreScope::{r["scope"]})?;')
            dispatch += head + f'''{scope_guard}
                {record_scope_guard(r)}
                facade_outside_room_turn(call, {json.dumps(name)})?;{" let caller = facade_actor(server, auth)?;" if r.get("host_door_caller") else ""}{" let landed_by = facade_actor(server, auth)?;" if lands else ""}
                let value = input?;
                oneiron::task_verb::sdk::validate_input({json.dumps(name)}, &value)?;
                {pre_hooks}
                {answer}
            }}\n'''
            continue
        # `readable` names the credential read checks: each caller-named ref is
        # refused before the engine call, and `rows` filters the typed result.
        room_guard, ref_guard = '', ''
        # A task-decision row invokes on its worker's own server and call.
        on = '&server, &call' if takes_task_decisions(r) else 'server, call'
        result = f'facade_invoke({on}, actor, class, "{name}", value, &producers)?'
        if takes_task_work_turn(r):
            # Rule 5: the engine call runs on the turn the dispatch awaited.
            result = f'facade_invoke_in_turn({on}, actor, class, "{name}", value, &producers, Some(turn))?'
        if r.get('admission', {}).get('born_record_scope') or r.get('admission', {}).get('claim_record_scope'):
            result = f'facade_invoke_born({on}, actor, class, "{name}", value, position, &producers)?'
        result += ';'
        readables = r.get('admission', {}).get('readable', [])
        # A room turn refuses an unserved verb before any credential lookup,
        # so the refusal says nothing about the target the lookup would read.
        if 'rows' in readables:
            room_guard += f'facade_outside_room_turn(call, "{name}")?;'
        elif readables:
            room_guard += f'facade_room_turn_serves(call, "{name}", oneiron::memory::RoomTurnHandle::serves("{name}"))?;'
        branch_turn = ''
        # FIX 1210: a row that declares record refs refuses a ref the caller
        # cannot read with the same NOT_FOUND, its row's own ref check
        # receipting it first, as its engine fn would have.
        receipted = [readable for readable in readables if readable != 'rows'] if 'refs' in r else []
        for readable in readables:
            if readable in receipted:
                continue
            if readable == 'rows':
                memory = 'credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()).listing_producers(&producers)'
                result = (f'facade_readable_task_rows(&server.vault, auth, oneiron::task_verb::sdk::{method}(&{memory}, facade_input(value)?)?)?;\n'
                          'let rows = Some(producers.take());')
                if name in TASK_PRODUCER_BRANCHES:
                    # Rule 5 (FIX 2166): a request taking the producer branch
                    # runs on the turn the dispatch awaited, held until its
                    # engine call returns.
                    branch_turn = (f'let turn = if {TASK_PRODUCER_BRANCHES[name]}(&value) {{ '
                                   'Some(Arc::new(server.admit_task_work(actor).await)) } else { None };\n')
                    result = (f'{{ let memory = {memory}; '
                              'let memory = match turn { Some(turn) => memory.with_task_work_turn(turn), None => memory };\n'
                              f'facade_readable_task_rows(&server.vault, auth, oneiron::task_verb::sdk::{method}(&memory, facade_input(value)?)?)? }};\n'
                              'let rows = Some(producers.take());')
            elif nested_readable(readable):
                # 2690: a nested path walks to each ref it names.
                ref_guard += f'facade_admit_readable_path(&server.vault, auth, &value, "{readable}")?;'
            else:
                ref_guard += f'facade_admit_readable_ref(&server.vault, auth, &value, "{readable}")?;'
        if receipted:
            fields = ', '.join(json.dumps(readable) for readable in receipted)
            ref_guard += f'facade_admit_receipted(server, call, actor, class, "{name}", &value, &[{fields}])?;'
        # A server door runs the verb with the host's execution inputs, off the
        # runtime, inside the room turn the call names, if any, and lists the
        # rows its answer is derived from without naming them.
        if r.get('server_door'):
            home_door = HOME_SERVER_DOORS.get(name)
            door_call = (f'{home_door}(actor, class, auth.verified_slip().cloned(), auth.destination(), call.room_turn()?, facade_input(value)?, call.home_caller())'
                         if home_door else f'{r["server_door"]}_listing(actor, class, auth.verified_slip().cloned(), auth.locality(), call.room_turn()?, facade_input(value)?)')
            result = (f'let (output, listed) = server.{door_call}.await;\n'
                      'let output = facade_output(output?)?;\nlet rows = Some(listed);')
        elif name in CALL_HOME_DOORS:
            result = (f'let (output, listed) = {CALL_HOME_DOORS[name][0]}(server, call, actor, class, facade_input(value)?).await;\n'
                      'let output = facade_output(output?)?;\nlet rows = Some(listed);')
        landed = ''
        if r.get('lands_turn'):
            landed = 'server.ai.turn_landed_by(server.vault(), actor, class);'
        # A born door's landing judges its record bounds, so only the grant is
        # left to check; so does a lane door whose engine door judges the
        # credential's lane in each snapshot (`require_granted_scope`).
        require = 'require_granted' if (r.get('admission', {}).get('born_record_scope') or r.get('admission', {}).get('claim_record_scope')
                                        or r.get('admission', {}).get('require_granted_scope')) else 'require'
        head += f'''auth.{require}(CoreScope::{r["scope"]})?;
        {record_scope_guard(r)}
        let value = input?;\n'''
        # A row that runs itself, not through `invoke`, crosses its verb hooks
        # here (ARCH-0080 §3): after the call's own refusals, before the checks
        # its args meet, so a rewrite meets them too. `invoke` crosses them for
        # every other row.
        if 'rows' in readables or r.get('server_door') or name in CALL_HOME_DOORS:
            actor = 'let (actor, class) = facade_actor(server, auth)?;'
            self_branch = ''
            if name == 'describe':
                # describe(self) renders the authenticated run brief, under no
                # actor, and lists the rows its card is derived from.
                # The one target check meets the args the hooks left (FIX 3256).
                self_branch = ('oneiron::task_verb::sdk::validate_input("describe", &value)?; '
                               'if value.get("self").and_then(serde_json::Value::as_bool) == Some(true) { '
                               'let (output, rows) = crate::api::context_board::describe_self_for_auth(server, auth, &value).await?; '
                               'return Ok((output, Some(rows))); } ' + actor)
                actor = ''
            door = r.get('server_door') or name in CALL_HOME_DOORS
            producers = '' if door else 'let producers = oneiron::memory::ProducerRows::default();\n'
            output = result if door else f'let output = {result}'
            # A row that fails after its pre chain ran (its target check, its
            # door, its input's decode or its answer's encoding) keeps a
            # session-only call's pre hook records and runs no post chain
            # (FIX 5651), as a host door does (FIX 5527).
            dispatch += head + f'''oneiron::task_verb::sdk::validate_input("{name}", &value)?;
        {room_guard}{actor}
        let hooks = facade_hooks_pre(server, call, "{name}", value).await?;
        let value = hooks.args.clone();
        let ran = async {{ {self_branch}{ref_guard}
        {branch_turn}{producers}{output}{landed}
        Ok::<_, FacadeApiError>((output, rows))
        }}.await;
        let (output, rows) = match ran {{ Ok(ran) => ran, Err(error) => {{ row_hooks_abort(server, hooks).await; return Err(error); }} }};
        Ok(FacadeCallOutput {{ value: facade_hooks_post(server, hooks, output).await?, rows }})
        }}\n'''
            continue
        # Rule 5: a task-work row's turn, bound on the surface its engine call
        # runs on and held until that call returns.
        turn = '\nlet turn = Arc::new(server.admit_task_work(actor).await);' if takes_task_work_turn(r) else ''
        if takes_task_decisions(r):
            # OF-533: after the call's own refusals, the whole invoke runs on a
            # blocking thread, its surface, rewrite admission, drain, room turn
            # and hooks with it as one row, since a model rung of the decision
            # ladder its surface binds may block on the server's runtime.
            dispatch += head + f'''let (actor, class) = facade_actor(server, auth)?;{room_guard}{ref_guard}{turn}
        let (server, owned) = (Arc::clone(server), call.owned());
        tokio::task::spawn_blocking(move || -> Result<FacadeCallOutput, FacadeApiError> {{
        let call = owned.call();
        let producers = oneiron::memory::ProducerRows::default();
        let output = {result}{landed}
        Ok(FacadeCallOutput::listed(output, &producers))
        }})
        .await
        .map_err(|_| FacadeApiError::from(super::host_doors::internal("{name}")))?
        }}\n'''
            continue
        dispatch += head + f'''let (actor, class) = facade_actor(server, auth)?;{room_guard}{ref_guard}{turn}
        let producers = oneiron::memory::ProducerRows::default();
        let output = {result}{landed}
        Ok(FacadeCallOutput::listed(output, &producers))
        }}\n'''
    # 2690: each row's nested readable paths, which a hook's rewrite meets
    # again (`facade_admit_rewritten_paths`), as a top-level `*_ref` does.
    nested = [(r['name'], [x for x in r.get('admission', {}).get('readable', []) if nested_readable(x)]) for r in facade_rows]
    dispatch += ('/// The nested `readable` paths of each facade row that declares one (2690):\n'
                 '/// a hook\'s rewrite of one meets its credential read check again.\n'
                 'const NESTED_READABLE: &[(&str, &[&str])] = &[' + ''.join(f'({json.dumps(verb)}, &[{", ".join(json.dumps(path) for path in paths)}]),' for verb, paths in nested if paths) + '];\n'
                 '/// [`NESTED_READABLE`]\'s paths for `verb`; none for a row that declares none.\n'
                 "pub(super) fn nested_readable_paths(verb: &str) -> &'static [&'static str] {\n"
                 'match NESTED_READABLE.iter().find(|(row, _)| *row == verb) { Some((_, paths)) => *paths, None => &[] }\n}\n')
    dispatch += f'''/// Runs facade verb `verb` for `call` over `input`, as its row admits it:
/// the one verb table every server transport serves. A board, browser or run
/// row is refused by the context it needs, which no facade call carries; any
/// other name is refused as an unknown verb, with its correction when it is a
/// canonical verb under the wrong root.
pub(crate) async fn call_verb(server: &Arc<SyncServer>, call: &FacadeCall<'_>, verb: &str, input: Result<serde_json::Value, FacadeApiError>) -> Result<FacadeCallOutput, FacadeApiError> {{
match verb {{
'''
    dispatch += ''.join(f'{json.dumps(r["name"])} => {r["name"].replace(".", "_")}(server, call, input).await,\n' for r in facade_rows)
    for context, rows in [('Board', [r for r in ROWS if r.get('context') == 'board' and 'host' not in r]), ('Browser', [r for r in BROWSER_ROWS if 'host' not in r]), ('Run', [r for r in RUN_ROWS if 'host' not in r])]:
        if rows: dispatch += ' | '.join(json.dumps(r['name']) for r in rows) + f' => Err(context_required(verb, VerbContext::{context})),\n'
    dispatch += '_ => Err(unknown_verb(verb)),\n}\n}\n'
    return routes, dispatch

def outputs():
    facade_rows = [r for r in ROWS if r.get("context", "memory") == "memory"] + BOARD_HOST_ROWS
    core = HEADER
    # A count default is stated once, on its manifest argument. The engine
    # reads it from here, and every binding signature is generated from the
    # same number.
    for r in ROWS:
        for a in r.get('binding', {}).get('args', []):
            if 'default' in a and ARGUMENTS[a['kind']]['rust'] == 'usize':
                core += f"/// `{r['name']}`'s `{a['name']}` when a caller names none.\npub const {default_const(r, a)}: usize = {a['default']};\n"
    core += "pub fn input_schema(verb: &str) -> Option<&'static serde_json::Value> {\n"
    # GLOBAL STATE: these schemas depend only on compiled verb types, never vault or actor data.
    # Sharing one immutable schema table avoids repeated schemars generation on tool listing.
    core += "// GLOBAL STATE: compiled verb schemas are immutable, vault-independent metadata; share one table across callers.\n"
    core += "static SCHEMAS: std::sync::LazyLock<std::collections::HashMap<&'static str, serde_json::Value>> = std::sync::LazyLock::new(|| std::collections::HashMap::from([\n"
    for r in SCHEMA_ROWS:
        core += f'({json.dumps(r["name"])}, crate::code_run::vault_read::request_schema::<{r["input"]}>()),\n'
    core += "])); SCHEMAS.get(verb) }\n"
    # DOOR-115: the rows the OpenAPI document publishes, and each one's answer
    # schema, read from its `output` type as `input_schema` reads its input.
    openapi_rows = [r for r in ROWS if r.get('openapi')] + [r for r in BOARD_HOST_ROWS if r.get('openapi')]
    core += "/// The facade rows the server's OpenAPI document publishes, each beside its\n/// [`input_schema`] and [`output_schema`].\n"
    core += "pub const OPENAPI_ROWS: &[&str] = &[" + ''.join(f'{json.dumps(r["name"])},' for r in openapi_rows) + "];\n"
    core += "/// The JSON schema of an [`OPENAPI_ROWS`] row's answer; `None` for any other row.\n"
    core += "pub fn output_schema(verb: &str) -> Option<serde_json::Value> { Some(match verb {\n"
    for r in openapi_rows:
        core += f'{json.dumps(r["name"])} => crate::code_run::vault_read::request_schema::<{r["output"]}>(),\n'
    core += "_ => return None, }) }\n"
    # A board row's facade door takes its host projection, not the board
    # shape `input_schema` states for MCP and code mode: the OpenAPI
    # document reads the facade shape from here.
    core += "/// The JSON schema of the input a verb's facade route takes; a board\n/// verb's host projection where it has one, else [`input_schema`].\n"
    core += "pub fn facade_input_schema(verb: &str) -> Option<serde_json::Value> { Some(match verb {\n"
    for r in BOARD_HOST_ROWS:
        core += f'{json.dumps(r["name"])} => crate::code_run::vault_read::request_schema::<{r["input"]}>(),\n'
    core += "_ => return input_schema(verb).cloned(), }) }\n"
    # DOOR-127: the rows whose calls keep no call receipt on any transport.
    core += "/// The facade rows no transport keeps a call receipt of (DOOR-127): an\n/// off-record session's own rows.\n"
    core += "pub const NO_RECORD_ROWS: &[&str] = &[" + ''.join(f'{json.dumps(r["name"])},' for r in ROWS if r.get('no_record')) + "];\n"
    core += "pub fn mcp_arguments_schema(verb: &str) -> Option<serde_json::Value> { mcp_arguments_schema_from_input(verb, input_schema(verb)?) }\n"
    core += "pub fn mcp_arguments_schema_from_input(verb: &str, schema: &serde_json::Value) -> Option<serde_json::Value> { let mut properties = serde_json::Map::new(); let required: &[&str] = match verb {\n"
    for r in mcp_rows():
        core += f'{json.dumps(r["name"])} => {{\n'
        for field, path in r['mcp_fields'].items():
            pointer = '' if path == '$' else ''.join('/properties/' + part for part in path.removeprefix('=').split('.'))
            if path == '$':
                core += f'if schema == &serde_json::Value::Bool(false) {{ return None; }}\n'
            core += f'properties.insert({json.dumps(field)}.to_owned(), schema.pointer({json.dumps(pointer)})?.clone());\n'
        core += '&' + json.dumps(list(r.get('mcp_required_fields', r['mcp_fields']))) + '},\n'
    core += '_ => return None, }; Some(serde_json::json!({"type": "object", "additionalProperties": false, "required": required, "properties": properties})) }\n'
    core += "pub fn validate_input(verb: &str, value: &serde_json::Value) -> MemoryResult<()> { match verb {\n"
    board_host_input = {r['name']: r['input'] for r in BOARD_HOST_ROWS}
    for r in ROWS:
        checks = r.get('admission', {}).get('validate', '')
        binding = 'input' if checks else '_input'
        if r['name'] in board_host_input:
            # One verb, two served shapes: the board/MCP shape and the
            # facade's host projection. Either admits; each door decodes
            # its own shape after this check.
            core += f'{json.dumps(r["name"])} => {{ if decode::<{r["input"]}>(value.clone()).is_err() {{ let _host: {board_host_input[r["name"]]} = decode(value.clone())?; }} }},\n'
        else:
            core += f'{json.dumps(r["name"])} => {{ let {binding}: {r["input"]} = decode(value.clone())?; {checks} }},\n'
    core += '_ => return Err(wrong_root(verb).unwrap_or_else(|| MemoryError::bad_request("unknown SDK agent verb"))), } Ok(()) }\n'
    # Code mode binds its own guest, so a rewrite there validates the original
    # browser input, never the public live-run attachment wrapper.
    core += "pub fn validate_browser_input(verb: &str, value: &serde_json::Value) -> MemoryResult<()> { match verb {\n"
    for r in BROWSER_ROWS:
        core += f'{json.dumps(r["name"])} => {{ let _input: {r["input"]} = decode(value.clone())?; }},\n'
    core += '_ => return Err(MemoryError::bad_request("a browser verb is required")), } Ok(()) }\n'
    # ARCH-0080 §3: every door that runs a row by name crosses its verb hooks
    # here, once; no caller of `invoke` wraps it again.
    core += "pub fn invoke(memory: &Memory<'_>, verb: &str, value: serde_json::Value) -> MemoryResult<serde_json::Value> {\n"
    core += 'if !AgentVerb::from_name(verb).is_some_and(AgentVerb::is_facade) { return Err(wrong_root(verb).unwrap_or_else(|| MemoryError::bad_request("unknown SDK agent verb"))); }\n'
    # G10: an embedded handle has no anonymous model host. Refuse it before
    # hooks can retain even a hash or an ask containing the anonymous input.
    core += 'if verb == "ai.anonymous_chat" { return encode(ai_anonymous_chat(memory, decode(value)?)?); }\n'
    core += "// The row's one verb-hook boundary (ARCH-0080 §3).\n"
    core += "crate::task_verb::verb_hook_boundary::row(memory, verb, value, |value| match verb {\n"
    for r in facade_rows:
        method = r['name'].replace('.', '_')
        if r.get('board_host'):
            # No memory fn of this name: it is the board fn's. An embedded
            # handle answers the host-only refusal, as other host rows do.
            core += f'{json.dumps(r["name"])} => encode(crate::task_verb::sdk::host_only::<{r["output"]}, {r["input"]}>(memory, {json.dumps(r["name"])}, &decode(value)?)?),\n'
        else:
            core += f'{json.dumps(r["name"])} => encode({method}(memory, decode(value)?)?),\n'
    core += '_ => Err(MemoryError::bad_request("unknown SDK agent verb")),\n})\n}\n'
    # A browser row's one door: code mode hands its whole input to the run's
    # browser session and takes the verb's whole output back.
    core += "pub fn invoke_browser(driver: &mut dyn oneiron_browser::BrowserDriver, verb: &str, value: serde_json::Value) -> Result<serde_json::Value, oneiron_browser::BrowserError> {\n"
    core += "let invalid = |error: serde_json::Error| oneiron_browser::BrowserError::Input(error.to_string());\n"
    core += "let output = match verb {\n"
    for r in BROWSER_ROWS:
        core += f'{json.dumps(r["name"])} => {{ let input: {r["input"]} = serde_json::from_value(value).map_err(invalid)?; let output = {r["call"]}; serde_json::to_value(output) }},\n'
    core += '_ => return Err(oneiron_browser::BrowserError::Input(format!("{verb} is not a browser verb"))),\n}; output.map_err(|error| oneiron_browser::BrowserError::Protocol(error.to_string())) }\n'
    for r in ROWS:
        method = r['name'].replace('.', '_')
        binding = '_input' if r['input'] == 'EmptyRequest' else 'input'
        checks = r.get('admission', {}).get('validate', '')
        call = r['call']
        result = prose_links_landed(r, call) or (call[:-1] if call.endswith('?') else f'Ok({call})')
        result = record_refs_check(r) + result
        result = prose_links_check(r) + result
        if r.get('context') == 'browser':
            core += f"pub fn {method}(driver: &mut dyn oneiron_browser::BrowserDriver, {binding}: {r['input']}) -> Result<{r['output']}, oneiron_browser::BrowserError> {{ {result} }}\n"
        elif r.get('context') == 'board':
            core += f"pub fn {method}<S: crate::board_verb::LiveBoardSource>(context: &mut crate::board_verb::BoardVerbContext<'_, S>, {binding}: {r['input']}) -> Result<{r['output']}, crate::board_verb::BoardVerbError> {{ {result} }}\n"
        else:
            core += f"pub fn {method}(memory: &Memory<'_>, {binding}: {r['input']}) -> MemoryResult<{r['output']}> {{ {checks} {result} }}\n"
    # FIX 1210: the record-ref check a row's engine fn runs before its call,
    # alone, for a door that refuses a ref its caller cannot read before that
    # fn runs: the refusal is receipted as the fn's would be, and no call runs.
    core += ("/// The record-ref check `verb`'s engine fn runs before its call, run alone\n"
             "/// (FIX 1210): a door that refused one of its refs before reaching the fn\n"
             "/// receipts that refusal as the fn would have. Its own checks of the input\n"
             "/// run first, as in the fn; no engine call runs. A verb whose door checks\n"
             "/// no readable ref checks nothing.\n"
             "pub fn receipt_declared_refs(memory: &Memory<'_>, verb: &str, value: serde_json::Value) -> MemoryResult<()> {\nmatch verb {\n")
    for r in ROWS:
        if 'refs' not in r or not [x for x in r.get('admission', {}).get('readable', []) if x != 'rows']:
            continue
        checks = r.get('admission', {}).get('validate', '')
        prose = prose_links_check(r).replace('let unlinked_prose =', 'let _unlinked_prose =')
        core += f'{json.dumps(r["name"])} => {{ let input: {r["input"]} = decode(value)?; {checks} {prose}{record_refs_check(r)}}}\n'
    core += '_ => {}\n}\nOk(())\n}\n'
    server, dispatch = facade_dispatch(facade_rows)
    remote = HEADER + 'use super::*;\n'
    remote += '''fn remote_agent_verb_output<R: serde::de::DeserializeOwned + serde::Serialize>(
        client: &RemoteClient, verb: &str, input: &serde_json::Value,
    ) -> Result<serde_json::Value, MemoryError> {
        let output: R = client.call(verb, input)?;
        serde_json::to_value(output).map_err(|error| crate::error::transport_error(
            format!("the remote SDK could not encode {verb}'s decoded result: {error}")
        ))
    }
'''
    remote += 'impl OneironClient {\n'
    remote += '''pub fn agent_verb(&self, verb: &str, input: serde_json::Value) -> Result<serde_json::Value, MemoryError> {
        self.ensure_dispatch_pid()?;
        if !oneiron::task_verb::sdk::AgentVerb::from_name(verb).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_facade) { return Err(oneiron::task_verb::sdk::wrong_root(verb).unwrap_or_else(|| crate::error::bad_request("unknown SDK agent verb", &["Use a verb from the SDK catalog."]))); }
        oneiron::task_verb::sdk::validate_input(verb, &input)?;
        match &self.backend {
            Backend::Embedded(client) => client.invoke(verb, input),
            Backend::Remote(client) => match verb {
'''
    for row in facade_rows:
        output = rust_type(row['output']) if not row['output'].startswith(('Vec<', 'Option<')) else row['output'].replace('crate::', 'oneiron::')
        remote += f'{json.dumps(row["name"])} => remote_agent_verb_output::<{output}>(client, verb, &input),\n'
    remote += '''_ => Err(crate::error::bad_request("unknown SDK agent verb", &["Use a verb from the SDK catalog."])),
        },
    }
}
'''
    remote += '''fn typed_agent_verb<R: serde::de::DeserializeOwned>(&self, verb: &str, input: serde_json::Value) -> Result<R, MemoryError> {
        match &self.backend {
            Backend::Remote(client) => {
                self.ensure_dispatch_pid()?;
                oneiron::task_verb::sdk::validate_input(verb, &input)?;
                client.call(verb, &input)
            }
            Backend::Embedded(_) => {
                let result = self.agent_verb(verb, input)?;
                serde_json::from_value(result).map_err(|error| crate::error::transport_error(
                    format!("the embedded SDK answered {verb} with a body this verb could not decode: {error}")
                ))
            }
        }
    }
'''
    for r in facade_rows:
        method=r['name'].replace('.','_')
        out=r['output'].replace('crate::', 'oneiron::')
        declaration, input_value, value_input = remote_boundary(r)
        # The typed check runs before encoding: JSON has no NaN, so a
        # non-finite float would reach validate_input as null.
        checks = r.get('admission', {}).get('validate', '').replace('crate::', 'oneiron::')
        if not value_input.startswith('&'):
            # Drop only the whole-request borrow; field borrows remain required.
            checks = re.sub(r'&\binput\b(?!\.)', value_input, checks)
            checks = re.sub(r'\binput\b', value_input, checks)
        remote += r.get('binding', {}).get('docs', {}).get('remote', '')
        params = 1 + (len(r['binding']['args']) if r.get('binding', {}).get('args') and r['binding'].get('wire') != 'json' else 1)
        remote += long_signature(params)
        remote += f'''pub fn {method}(&self, {declaration}) -> Result<{out}, MemoryError> {{
            {input_value}{checks}
            let value = serde_json::to_value({value_input}).map_err(|_| crate::error::bad_request("SDK input encoding failed", &["Send the documented typed SDK input."]))?;
            self.typed_agent_verb("{r["name"]}", value)
        }}\n'''
    remote += '}\n'
    # `#[napi]` copies a method's attributes onto the glue it generates, where
    # the lint never fires, so a long verb's expectation sits on the module.
    long_napi = any(len(native_args(r)) + 1 > 7 for r in facade_rows)
    napi = HEADER + (f'#![{LONG_SIGNATURE}]\n' if long_napi else '') + 'use super::*;\n#[napi]\nimpl NativeClient {\n'
    py = ''
    for r in facade_rows:
        method=r['name'].replace('.','_')
        napi += native_boundary(r, 'napi')
        py += native_boundary(r, 'py')
    napi += '}\n'
    ts = HEADER + AGENT_VERBS_TS
    ts_native = '\n'.join(ts_native_signature(r) for r in facade_rows)
    variants = {r['name']: ''.join(part.title() for part in r['name'].replace('.', '_').split('_')) for r in ROWS}
    catalog = HEADER + '#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum AgentVerb { '
    catalog += ','.join(variants.values()) + ' }\nimpl AgentVerb {\n'
    catalog += 'pub const ALL: &[Self] = &[' + ','.join('Self::' + variant for variant in variants.values()) + '];\n'
    catalog += "pub fn from_name(name: &str) -> Option<Self> { Self::ALL.iter().copied().find(|verb| verb.as_str() == name) }\n"
    catalog += "pub const fn as_str(self) -> &'static str { match self {\n"
    catalog += ''.join('Self::' + variants[r['name']] + ' => ' + json.dumps(r['name']) + ',\n' for r in ROWS) + '} }\n'
    for method, select in [
        ('is_facade', lambda r: r.get('context', 'memory') == 'memory' or r['name'] in BOARD_HOST_NAMES),
        ('is_browser', lambda r: r['name'] in {row['name'] for row in BROWSER_ROWS}),
        ('is_mcp', lambda r: r.get('mcp') != 'none'),
        ('is_section', lambda r: r['section']),
        ('continuable', lambda r: r.get('mcp_page', 'page' in r or r['output'].startswith('Vec<'))),
        ('filtered_read', lambda r: r['mcp_scope'] == 'filtered'),
        ('requires_unscoped', lambda r: r['mcp_scope'] == 'unrestricted'),
        ('born_in_scope', lambda r: r['mcp_scope'] == 'born'),
        ('writes', lambda r: r['scope'] == 'Write'),
        ('proposes', lambda r: r.get('proposes', False)),
        ('is_task_work', lambda r: r.get('task_work', False)),
        ('takes_task_decisions', takes_task_decisions),
    ]:
        selected = ['Self::' + variants[r['name']] for r in ROWS if select(r)]
        catalog += f'pub const fn {method}(self) -> bool {{ matches!(self, ' + (' | '.join(selected) if selected else '_ if false') + ') }\n'
    for method, field in [('argument_fields', 'mcp_fields'), ('required_fields', 'mcp_required_fields')]:
        catalog += f"pub const fn {method}(self) -> &'static [&'static str] {{ match self {{\n"
        for r in ROWS:
            catalog += 'Self::' + variants[r['name']] + ' => &' + json.dumps(list(r.get(field, r['mcp_fields']))) + ',\n'
        catalog += '} }\n'
    # OF-246: the row's one line, as the MCP tool list and every client read
    # it; empty for a row that states none.
    catalog += "/// The row's one-line description, as the verb table states it.\n"
    catalog += "pub const fn description(self) -> &'static str { match self {\n"
    catalog += ''.join('Self::' + variants[r['name']] + ' => ' + json.dumps(r.get('description', '')) + ',\n' for r in ROWS)
    catalog += '} }\n'
    catalog += '}\n'
    uniffi, uniffi_types = uniffi_facade(facade_rows)
    http = http_facade()
    files = {
        'packages/oneiron-client/src/facade.ts': http,
        'crates/oneiron/src/verbs/generated/run_verb_catalog.rs': run_catalog(),
        'crates/oneiron-uniffi/src/generated/facade_generated.rs': uniffi,
        'crates/oneiron-uniffi/src/generated/facade_types_generated.rs': uniffi_types,
        'crates/oneiron/src/verbs/generated/sdk_generated.rs':core,
        'crates/oneiron/src/verbs/generated/verb_catalog.rs':catalog,
        'crates/oneiron-server/src/api/facade/generated/agent_verbs.rs':server,
        'crates/oneiron-server/src/api/facade/generated/dispatch.rs':dispatch,
        'crates/oneiron-remote/src/generated/agent_verbs.rs':remote,
        'crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs':napi,
        # FIX 8907: the MCP dispatch is a whole-file child of tasks_response.
        'crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs': HEADER + 'use super::*;\n' + mcp_dispatch(),
        'packages/oneiron/src/agent-verbs.ts':ts,
    }
    # FIX 8907: the old marked MCP block gives way to the seam that mounts
    # the whole-file dispatch above; once replaced, no marker remains.
    mcp_path = 'crates/oneiron-server/src/api/mcp_gateway/tasks_response.rs'
    mcp_text = (ROOT / mcp_path).read_text()
    mcp_begin = '// BEGIN GENERATED MCP DISPATCH'
    mcp_end = '// END GENERATED MCP DISPATCH'
    if mcp_begin in mcp_text:
        a = mcp_text.index(mcp_begin)
        b = mcp_text.index(mcp_end, a) + len(mcp_end)
        seam = (
            'use super::{board_setup, skill_execution, verb_hooks};\n'
            '#[path = "generated/agent_verb_dispatch.rs"]\n'
            'mod agent_verb_dispatch;\n'
            'use agent_verb_dispatch::execute_mcp_agent_verb;\n'
            'pub(crate) use agent_verb_dispatch::{execute_agent_verb_input, mcp_agent_verb_arguments};'
        )
        files[mcp_path] = mcp_text[:a] + seam + mcp_text[b:]
    for path, start, end, body in [
        ('crates/oneiron/src/board_verb.rs', '// BEGIN GENERATED BOARD CATALOG', '// END GENERATED BOARD CATALOG', None),
        ('crates/oneiron-py/python/oneiron/__init__.pyi', '# BEGIN GENERATED FACADE VERBS', '# END GENERATED FACADE VERBS', python_class_verbs(verb_tree(facade_rows), stub=True)),
        ('packages/oneiron/src/index.ts', '// BEGIN GENERATED FACADE VERBS', '// END GENERATED FACADE VERBS', ts_class_verbs(verb_tree(facade_rows))),
        ('crates/oneiron-py/python/oneiron/__init__.py', '# BEGIN GENERATED FACADE VERBS', '# END GENERATED FACADE VERBS', python_class_verbs(verb_tree(facade_rows))),
        ('crates/oneiron-py/src/lib.rs', '// BEGIN GENERATED AGENT VERBS', '// END GENERATED AGENT VERBS', py),
        ('packages/oneiron/src/native.ts', '// BEGIN GENERATED AGENT VERBS', '// END GENERATED AGENT VERBS', ts_native),
    ]:
        text=(ROOT/path).read_text()
        if body is None and start not in text: continue
        a=text.index(start)+len(start); b=text.index(end,a)
        files[path]=text[:a]+'\n'+body+'\n'+text[b:] if body is not None else text[:a-len(start)]+text[b+len(end):]
    # Rendered last: every emitter above has named the types it uses. OF-181:
    # the hand-written lens-frame helpers (`POST
    # /v1/core/lens-frames/{card_id}/events`, no verb row) name the engine's
    # event, so it is a root here; their reply's `$state` and receipt are
    # reached already.
    INVENTORY.root_ir('crate::lens::GeneratedUiActionEvent')
    # FIX 365: the hand-written transcript route (`GET
    # /v1/core/conversations/{conversation_id}/transcript`, no verb row)
    # answers with the engine's page, whose MESSAGE carries a typed result;
    # the result is a root of its own for `POST
    # /v1/core/messages/{message}/result`, which reads the body it names.
    INVENTORY.root_ir('crate::memory::TranscriptPage')
    INVENTORY.root_ir('crate::memory::MessageResultAttachment')
    census = INVENTORY.census(FACADE_ROWS)
    facade_types = INVENTORY.typescript(census)
    files['packages/oneiron/src/facade-types.ts'] = facade_types
    files['packages/oneiron-client/src/facade-types.ts'] = facade_types
    files['crates/oneiron-py/python/oneiron/facade_types.pyi'] = INVENTORY.python(census)
    # ONE-2510 S2: the code-mode catalog fragment over every row code mode
    # serves, at catalog_fragment.d.ts and at code-mode.d.ts, with its
    # revision; its own inventory leaves the facade types above as they are.
    files.update(catalog_fragment(ROOT, CODE_MODE_ROWS, HEADER))
    for path, text in list(files.items()):
        if path.endswith('.rs'):
            result = subprocess.run(['rustfmt', '--edition', '2024', '--emit', 'stdout'], input=text, text=True, capture_output=True, cwd=ROOT, check=True)
            files[path] = result.stdout
    files.update({path: None for path in ['crates/oneiron/src/workspace_roster/rooms/verb_catalog.rs', 'crates/oneiron-server/src/mcp/agent_catalog.rs', 'crates/oneiron-py/python/oneiron/agent_verbs.py', 'crates/oneiron-py/python/oneiron/agent_verbs.pyi',
        # FIX 8907: the whole-file outputs' homes before generated/.
        'crates/oneiron/src/task_verb/verb_catalog.rs',
        'crates/oneiron/src/task_verb/run_verb_catalog.rs',
        'crates/oneiron/src/task_verb/sdk_generated.rs',
        'crates/oneiron/src/task_verb/catalog_fragment_revision.rs',
        'crates/oneiron-server/src/api/facade/agent_verbs.rs',
        'crates/oneiron-server/src/api/facade/dispatch.rs',
        'crates/oneiron-remote/src/agent_verbs.rs',
        'crates/oneiron-napi/src/facade/client/agent_verbs.rs',
        'crates/oneiron-uniffi/src/facade_generated.rs',
        'crates/oneiron-uniffi/src/facade_types_generated.rs',
        'crates/oneiron/src/task_verb/catalog_fragment.d.ts',
        'crates/oneiron/src/task_verb/code-mode.d.ts']})
    return files

# OF-237: the UniFFI binding. Every facade row is one exported method of the
# UniFFI `Oneiron` handle whose body calls the shared `OneironClient`'s typed
# method for the row, so an embedded handle and a connected one answer it the
# way napi and Python do. A row's `uniffi` block spells its typed foreign
# signature over the crate's records. A row without one projects by type: an
# engine type with a hand-written UniFFI record (`dto.rs`) crosses as that
# record, a typed binding argument as its foreign value, and any other input
# or output as the generated record of its type from the facade type inventory
# (`uniffi_types.py`, `facade_types_generated.rs`), converted through the
# shared wire shape. An input record with no fields is no argument at all. Only
# a type the inventory could not read crosses as the crate's `WireJson` leaf,
# parsed into the row's engine input type and written from its typed output on
# the Rust side; there is no generic `call`. A definition row gets no UniFFI
# export: the generator refuses one until the table gives it a call.
# Codecs are selected by type (`crates/oneiron-uniffi/src/codec.rs`), never by
# verb name.
UNIFFI_INPUTS = {
    'crate::memory::WitnessTurn': 'WitnessTurn',
    'crate::memory::ClaimInput': 'ClaimInput',
    'crate::memory::ClaimListFilter': 'ClaimListFilter',
    'crate::memory::StructuralPutInput': 'StructuralPutInput',
    'crate::memory::HabitCheckinInput': 'HabitCheckinInput',
    'crate::memory::AdmitImportedClaimInput': 'AdmitImportedClaimInput',
    'crate::memory::BlobArtifactInput': 'BlobArtifactInput',
}
UNIFFI_RESULTS = {
    'crate::memory::WitnessReceipt': 'WitnessReceipt',
    'crate::memory::CommitReceipt': 'CommitReceipt',
    'crate::memory::MemoryPack': 'MemoryPack',
    'crate::memory::MemoryReceipt': 'FacadeReceipt',
    'crate::memory::DeleteReceipt': 'DeleteReceipt',
    'crate::memory::PendingWrite': 'PendingWrite',
    'crate::memory::EntityRefReceipt': 'EntityRefReceipt',
    'crate::memory::BlobVersionView': 'BlobVersionView',
    'crate::memory::OutboundIntentReceipt': 'OutboundIntentReceipt',
    'crate::task_verb::sdk::BlobContent': 'Vec<u8>',
    'crate::claim::ScopedReadResult<Vec<crate::memory::ClaimView>>': 'ClaimViews',
    'crate::claim::ScopedReadResult<Vec<crate::memory::EntityView>>': 'EntityViews',
    'crate::claim::ScopedReadResult<Option<crate::memory::EntityView>>': 'EntityRead',
    'crate::claim::ScopedReadResult<Vec<crate::memory::LexicalHit>>': 'LexicalHits',
    'crate::claim::ScopedReadResult<Vec<crate::memory::NeighborHit>>': 'NeighborHits',
}
# A typed binding argument the client takes as is: its foreign type and how it
# is passed. Any other binding argument is lowered into its `ARGUMENTS` type.
UNIFFI_ARGUMENTS = {
    'text': ('String', '&{name}'),
    'ref': ('Option<String>', '{name}.as_deref()'),
    'format': ('Option<String>', '{name}.as_deref()'),
    'as_of': ('Option<u64>', '{name}'),
    'deadline_ms': ('Option<u64>', '{name}'),
    'kinds': ('Option<Vec<String>>', '{name}.as_deref().unwrap_or_default()'),
}

# FIX 3297: the hand-written lens-frame calls (lib.rs `lens_frame_event`,
# `close_lens_frame`; no verb row) cross the generated records of the client
# crate's bodies, under these names. `retry` stays WireJson by design: it
# carries any verb's shape.
UNIFFI_LENS_ROOTS = {
    'oneiron_remote::LensFrameEventRequest': 'LensFrameEventRequest',
    'oneiron_remote::LensFrameEventReply': 'LensFrameEventReply',
    'oneiron_remote::CloseLensFrameReply': 'CloseLensFrameReply',
}

def uniffi_record(value, records):
    'The UniFFI type an engine type crosses as, or None when it has no record.'
    for container in ('Option', 'Vec'):
        if value.startswith(container + '<') and value.endswith('>'):
            inner = uniffi_record(value[len(container) + 1:-1], records)
            return inner and f'{container}<{inner}>'
    return records.get(value)

# What a generated UniFFI type may not be named: the crate's hand-written
# exports, and what the crate root already binds.
UNIFFI_HAND_WRITTEN = ['crates/oneiron-uniffi/src/dto.rs', 'crates/oneiron-uniffi/src/lib.rs', 'crates/oneiron-uniffi/src/error.rs']
UNIFFI_ROOT_NAMES = ['Arc', 'Lift', 'Lower', 'UniFfiTag']

def uniffi_taken():
    names = set(UNIFFI_ROOT_NAMES)
    for path in UNIFFI_HAND_WRITTEN:
        names.update(re.findall(r'(?m)^pub (?:struct|enum) (\w+)', (ROOT/path).read_text()))
    return names

def uniffi_export(row, types, census):
    'One `export_facade!` arm: lower the arguments, call the typed client method, lift.'
    name, method = json.dumps(row['name']), row['name'].replace('.', '_')
    signature = row.get('uniffi')
    if 'call' not in row:
        # Every UniFFI row is callable (the last definition rows took calls in
        # #2049), so the binding keeps no fail-closed stub for one.
        raise ValueError(f'{row["name"]}: a definition row has no UniFFI export until it takes a call')
    binding = row.get('binding') or {}
    typed_args = binding['args'] if binding.get('args') and binding.get('wire') != 'json' else None
    engine_input = rust_type(row['input'])
    setup, values = [], []
    if signature:
        params, output, result = dict(signature['args']), signature['output'], 'Lift::lift(output)'
        if typed_args:
            if list(params) != [a['name'] for a in typed_args]:
                raise ValueError(f'{row["name"]}: its uniffi arguments are its binding arguments, in order')
            for a in typed_args:
                if a['kind'] in UNIFFI_ARGUMENTS:
                    values.append(UNIFFI_ARGUMENTS[a['kind']][1].format(name=a['name']))
                    continue
                target = ARGUMENTS[a['kind']]['rust']
                setup.append(f'let {a["name"]}: {target.lstrip("&")} = {a["name"]}.lower()?;')
                values.append(('&' if target.startswith('&') else '') + a['name'])
        else:
            lowered = next(iter(params)) if len(params) == 1 else '(' + ', '.join(params) + ')'
            setup.append(f'let input: {engine_input} = {lowered}.lower()?;')
            values.append('&input')
        census.setdefault(('typed', 'typed'), []).append(row['name'])
    else:
        if typed_args:
            unknown = [a['kind'] for a in typed_args if a['kind'] not in UNIFFI_ARGUMENTS]
            if unknown: raise ValueError(f'{row["name"]}: no UniFFI projection for binding argument kinds {unknown}')
            params = {a['name']: UNIFFI_ARGUMENTS[a['kind']][0] for a in typed_args}
            values = [UNIFFI_ARGUMENTS[a['kind']][1].format(name=a['name']) for a in typed_args]
            sides = ['typed']
        elif uniffi_record(row['input'], UNIFFI_INPUTS):
            params = {'input': uniffi_record(row['input'], UNIFFI_INPUTS)}
            setup.append(f'let input: {engine_input} = input.lower()?;')
            values.append('&input')
            sides = ['typed']
        elif types.root_is_empty(row['input']):
            params = {}
            setup.append(f'let input: {engine_input} = crate::codec::lower_empty({name})?;')
            values.append('&input')
            sides = ['generated']
        elif mirror := types.root(row['input']):
            params = {'input': mirror}
            setup.append(f'let input: {engine_input} = crate::codec::lower_record({name}, input)?;')
            values.append('&input')
            sides = ['generated']
        else:
            params = {'input': 'WireJson'}
            setup.append(f'let input: {engine_input} = crate::codec::decode({name}, &input)?;')
            values.append('&input')
            sides = ['wire']
        record = uniffi_record(row['output'], UNIFFI_RESULTS)
        if record:
            output, result = record, 'Lift::lift(output)'
            sides.append('typed')
        elif mirror := types.root(row['output']):
            output, result = mirror, f'crate::codec::lift_record({name}, &output)'
            sides.append('generated')
        else:
            output, result = 'WireJson', f'crate::codec::encode({name}, &output)'
            sides.append('wire')
        census.setdefault(tuple(sides), []).append(row['name'])
    declaration = ', '.join(arg + ': ' + typ for arg, typ in params.items())
    body = ''.join(f'    {line}\n' for line in setup + [f'let output = client.{method}({", ".join(values)})?;', result])
    receiver = f'&self, {declaration}' if declaration else '&self'
    return f'{name} => fn {method}({receiver}) -> {output} = |client| {{\n{body}}};\n'

def uniffi_facade(facade_rows):
    'The UniFFI verb surface (every facade row; a definition row is refused) and its generated types.'
    rows = facade_rows + [row for row in DEFINITIONS if 'uniffi' in row]
    if any('uniffi' in row for row in ROWS if row not in facade_rows):
        raise ValueError('only a facade row carries a uniffi signature')
    types, census = UniffiTypes(INVENTORY, uniffi_taken()), {}
    arms = ''.join(uniffi_export(row, types, census) for row in rows)
    for text, name in UNIFFI_LENS_ROOTS.items():
        if types.root(text) != name:
            raise ValueError(f'{text}: lib.rs crosses it as the generated record {name}, which it does not read as')
    count = lambda *sides: len(census.get(sides, []))
    lines = [
        f'UniFFI census: {len(facade_rows)} facade rows, {len(types.items)} generated types.',
        f'Hand-written records in and out: {count("typed", "typed")}; typed arguments or a hand-written input with a '
        f'generated result: {count("typed", "generated")}; a generated input with a hand-written result: {count("generated", "typed")}; '
        f'generated in and out: {count("generated", "generated")}.',
        'WireJson rows: ' + (', '.join(f'{name} ({"input" if sides[0] == "wire" else ""}{" and " if sides == ("wire", "wire") else ""}{"result" if sides[1] == "wire" else ""})'
                                       for sides, names in sorted(census.items()) if 'wire' in sides for name in names) or 'none') + '.',
        'WireJson leaves inside the generated types, past each serde_json::Value: '
        + (', '.join(f'{where} ({why})' for where, why in sorted(types.leaves.items())) or 'none') + '.',
    ]
    return HEADER + 'export_facade! {\n' + arms + '}\n', types.render(HEADER, lines)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    stale=[]
    for path,text in outputs().items():
        p=ROOT/path
        if text is None:
            if p.exists():
                stale.append(path)
                if not args.check: p.unlink()
            continue
        if p.exists() and p.read_text()==text:continue
        stale.append(path)
        if not args.check:
            p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    if args.check and stale:
        raise SystemExit('SDK-GENERATED-STALE: '+', '.join(stale))
    # OF-246: how many row types read fully, and each leaf that did not.
    if not args.check:
        print('\n'.join(INVENTORY.census(FACADE_ROWS)))
        for where, text in INVENTORY.opaques: print(f'  opaque: {where} ({text})')
        for where, text, reason in INVENTORY.fallbacks: print(f'  unread: {where} ({text}): {reason}')
if __name__=='__main__': main()
