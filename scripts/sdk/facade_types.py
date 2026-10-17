"""The facade's wire types, read from the Rust serde types every facade row names.

Each callable facade row in agent-verbs.json names an input and an output type.
Those are the roots: this module walks each root's Rust definition across the
engine crates' sources, follows every type it reaches (structs, unit, tuple,
newtype and struct variants, external/internal/adjacent/untagged enums, type
aliases, generic parameters, `serde` renames, defaults, skips, flattens, tags,
`from`/`into` and id codecs) and emits one declaration per Rust type, once, for
TypeScript and for the Python stubs alike. There is no second table of shapes:
the verb table names the roots and the Rust sources say the rest.

A shape it cannot read becomes `unknown` (`Any` in Python) and is listed in the
census with its reason; `serde_json::Value` is opaque by design and counted
apart.
"""
import json
import keyword
import re
import sys
from pathlib import Path

# A type chain is walked depth first; the engine's deepest ones need the room.
sys.setrecursionlimit(20000)

# The crates a facade type can live in, by the name a Rust path gives them.
CRATES = {
    'oneiron': 'crates/oneiron/src',
    'oneiron_contracts': 'crates/oneiron-contracts/src',
    'oneiron_authority': 'crates/oneiron-authority/src',
    'oneiron_crypto': 'crates/oneiron-crypto/src',
    'oneiron_model': 'crates/oneiron-model/src',
    'oneiron_retrieval': 'crates/oneiron-retrieval/src',
    'oneiron_vault_contract': 'crates/oneiron-vault-contract/src',
    'oneiron_sandbox_contract': 'crates/oneiron-sandbox-contract/src',
    'oneiron_browser': 'crates/oneiron-browser/src',
    'oneiron_docedit': 'crates/oneiron-docedit/src',
    'oneiron_xlsx_formula': 'crates/oneiron-xlsx-formula/src',
    'oneiron_keystore': 'crates/oneiron-keystore/src',
    'oneiron_code_check': 'crates/oneiron-code-check/src',
    'oneiron_container': 'crates/oneiron-container/src',
    'oneiron_spawn': 'crates/oneiron-spawn/src',
    'oneiron_guest': 'crates/oneiron-guest/src',
}
# Read up front; any other crate is read the first time a path names it.
EAGER = ('oneiron', 'oneiron_contracts', 'oneiron_authority', 'oneiron_model', 'oneiron_retrieval')
# A bare row type is named from the SDK module, as its generated fn names it.
ROOT_CONTEXT = ('oneiron', 'crates/oneiron/src/task_verb/sdk.rs')

INT = ('prim', 'int')
# An integer leaf also names its Rust width, which a typed binding (UniFFI)
# keeps; the TypeScript and Python projections read only `node[1]`.
def width(name):
    return ('prim', 'int', name)
FLOAT = ('prim', 'float')
STRING = ('prim', 'string')
BOOL = ('prim', 'bool')
NULL = ('prim', 'null')
OPAQUE = ('opaque',)

# Types of std and of external crates, by the last segment of their path.
LEAVES = {
    **{name: width(name) for name in ('u8', 'u16', 'u32', 'u64', 'u128', 'usize', 'i8', 'i16', 'i32', 'i64', 'i128', 'isize',
                                      'NonZeroU8', 'NonZeroU16', 'NonZeroU32', 'NonZeroU64', 'NonZeroUsize', 'NonZeroI64', 'NonZeroI32')},
    **{name: FLOAT for name in ('f32', 'f64', 'OrderedFloat', 'NotNan', 'Number')},
    **{name: STRING for name in ('String', 'str', 'char', 'PathBuf', 'Path', 'OsString', 'Uuid', 'Url', 'Version', 'IpAddr',
                                 'Ipv4Addr', 'Ipv6Addr', 'SocketAddr', 'SmolStr', 'CompactString', 'ArcStr', 'DateTime', 'Mime', 'HeaderValue')},
    'bool': BOOL,
    'PhantomData': NULL,
    'Value': OPAQUE,
    'RawValue': OPAQUE,
    'Duration': ('object', [('secs', width('u64'), False), ('nanos', width('u32'), False)], None),
    'SystemTime': ('object', [('secs_since_epoch', width('u64'), False), ('nanos_since_epoch', width('u32'), False)], None),
}
# Names a Rust file uses without importing them.
PRELUDE = {'String', 'Vec', 'Option', 'Box', 'Result', 'bool', 'str', 'char', 'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
           'i8', 'i16', 'i32', 'i64', 'i128', 'isize', 'f32', 'f64'}
WRAPPERS = {'Box', 'Arc', 'Rc', 'Cow', 'Zeroizing', 'Reverse', 'Wrapping', 'Cell', 'RefCell'}
SEQUENCES = {'Vec', 'VecDeque', 'HashSet', 'BTreeSet', 'IndexSet', 'SmallVec', 'ArrayVec', 'ThinVec', 'LinkedList', 'BinaryHeap', 'NonEmpty', 'Bytes', 'ByteBuf'}
MAPS = {'HashMap', 'BTreeMap', 'IndexMap', 'FxHashMap', 'AHashMap', 'Map'}
EXTERNAL = {'std', 'core', 'alloc', 'serde_json', 'serde', 'chrono', 'uuid', 'url', 'bytes', 'serde_bytes', 'smallvec', 'indexmap',
            'ordered_float', 'zeroize', 'time', 'semver', 'arrayvec', 'thin_vec', 'smol_str', 'compact_str', 'mime', 'http', 'nonempty'}
# Names a declaration may not take: TypeScript globals and the stub's own imports.
RESERVED = {'Record', 'Partial', 'Required', 'Readonly', 'Pick', 'Omit', 'Array', 'Map', 'Set', 'Promise', 'Response', 'Request',
            'Date', 'Error', 'Object', 'String', 'Number', 'Boolean', 'Symbol', 'Function', 'RegExp', 'JSON', 'Math', 'Uint8Array',
            'Headers', 'URL', 'Blob', 'File', 'Event', 'Node', 'Element', 'Text', 'Document', 'Window', 'Location', 'Storage',
            'Any', 'Literal', 'TypedDict', 'NotRequired', 'Generic', 'TypeVar', 'Facade', 'None', 'Self'}


# ---------------------------------------------------------------- Rust text

def _raw_string_end(text, i):
    'If a raw string starts at i, the index past its close; else None.'
    j = i + 1 if text[i] == 'r' else i + 2
    hashes = 0
    while j < len(text) and text[j] == '#':
        hashes += 1; j += 1
    if j >= len(text) or text[j] != '"':
        return None
    close = text.find('"' + '#' * hashes, j + 1)
    return len(text) if close < 0 else close + 1 + hashes


def _skip(text, i):
    'Past a string, char literal or comment at i; i itself when none starts there.'
    c = text[i]
    if c == '"':
        j = i + 1
        while j < len(text):
            if text[j] == '\\': j += 2; continue
            if text[j] == '"': return j + 1
            j += 1
        return len(text)
    if c == '/' and text.startswith('//', i):
        j = text.find('\n', i)
        return len(text) if j < 0 else j
    if c == '/' and text.startswith('/*', i):
        depth, j = 0, i
        while j < len(text):
            if text.startswith('/*', j): depth += 1; j += 2; continue
            if text.startswith('*/', j):
                depth -= 1; j += 2
                if depth == 0: return j
                continue
            j += 1
        return len(text)
    if c == "'":
        if text.startswith('\\', i + 1):
            j = text.find("'", i + 3)
            return i + 1 if j < 0 else j + 1
        if i + 2 < len(text) and text[i + 2] == "'":
            return i + 3
        return i + 1
    if c in 'rb' and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_')):
        if text.startswith('r"', i) or text.startswith('r#', i) or text.startswith('br"', i) or text.startswith('br#', i):
            end = _raw_string_end(text, i)
            if end: return end
    return i


def close_of(text, i):
    'The index past the bracket that closes the one at i, skipping strings and comments.'
    depth = 0
    while i < len(text):
        j = _skip(text, i)
        if j != i:
            i = j; continue
        c = text[i]
        if c in '([{': depth += 1
        elif c in ')]}':
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return len(text)


def strip_comments(text):
    out, i, start = [], 0, 0
    while i < len(text):
        if text.startswith('//', i) or text.startswith('/*', i):
            out.append(text[start:i]); i = _skip(text, i); start = i; continue
        j = _skip(text, i)
        i = j if j != i else i + 1
    out.append(text[start:])
    return ''.join(out)


def split_top(text, sep=','):
    'Splits at `sep` outside brackets, angle brackets and strings.'
    parts, depth, start, i = [], 0, 0, 0
    while i < len(text):
        j = _skip(text, i)
        if j != i:
            i = j; continue
        c = text[i]
        if c == '-' and text.startswith('->', i):
            i += 2; continue
        if c in '([{<': depth += 1
        elif c in ')]}>': depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i]); start = i + 1
        i += 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def leading_attrs(chunk):
    'A chunk\'s leading `#[...]` attributes as one string, and the rest of it.'
    attrs, rest = [], chunk.strip()
    while rest.startswith('#['):
        end = close_of(rest, 1)
        attrs.append(rest[:end]); rest = rest[end:].strip()
    return ' '.join(attrs), rest


def attr_args(attrs, name):
    'The merged `name(...)` arguments in the attributes, as key -> value (or True).'
    found = {}
    for match in re.finditer(r'\b' + name + r'\s*\(', attrs):
        start = match.end() - 1
        inner = attrs[start + 1:close_of(attrs, start) - 1]
        for part in split_top(inner):
            pair = re.match(r'(\w+)\s*=\s*(.*)$', part, re.S)
            nested = re.match(r'(\w+)\s*\(', part)
            if pair:
                value = pair.group(2).strip()
                found[pair.group(1)] = json.loads(value) if value.startswith('"') else value
            elif nested:
                found[nested.group(1)] = attr_args(part, nested.group(1)) or True
            else:
                found[part.strip()] = True
    return found


def derives(attrs):
    names = set()
    for match in re.finditer(r'derive\s*\(', attrs):
        start = match.end() - 1
        names.update(part.rsplit('::', 1)[-1] for part in split_top(attrs[start + 1:close_of(attrs, start) - 1]))
    return names


def rename(name, case, variant):
    'serde\'s `rename_all`: a variant name is PascalCase, a field name snake_case.'
    if not case: return name
    words = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower().split('_') if variant else name.split('_')
    if case == 'lowercase': return name.lower() if variant else name
    if case == 'UPPERCASE': return name.upper()
    if case == 'PascalCase': return name if variant else ''.join(w.title() for w in words)
    if case == 'camelCase':
        pascal = name if variant else ''.join(w.title() for w in words)
        return pascal[:1].lower() + pascal[1:]
    if case == 'snake_case': return '_'.join(words)
    if case == 'SCREAMING_SNAKE_CASE': return '_'.join(words).upper()
    if case == 'kebab-case': return '-'.join(words)
    if case == 'SCREAMING-KEBAB-CASE': return '-'.join(words).upper()
    return name


def codec_of(serde):
    'The codec a field is read through, when it names one.'
    return serde.get('with') or serde.get('deserialize_with')


def serialize_case(value):
    'A `rename_all`/`rename` value, or its `serialize = ...` half.'
    if isinstance(value, dict): return value.get('serialize')
    return value if isinstance(value, str) else None


# ---------------------------------------------------------------- Rust types

TOKEN = re.compile(r"\s*(::|->|'[A-Za-z_]\w*|r#\w+|[A-Za-z_]\w*|\d+|.)", re.S)


def parse_type(text):
    'A Rust type as a tree: ("path", segments, args), ("tuple", items), ("array", item), ("ref", item) or ("raw", text).'
    tokens = [t for t in TOKEN.findall(text) if t.strip()]
    position = 0

    def peek(offset=0):
        return tokens[position + offset] if position + offset < len(tokens) else None

    def take():
        nonlocal position
        position += 1
        return tokens[position - 1]

    def until_close(open_, close):
        depth = 1
        while peek() is not None and depth:
            token = take()
            depth += token == open_
            depth -= token == close

    def args():
        out = []
        while peek() not in ('>', None):
            if peek().startswith("'"):
                take()
            elif peek(1) == '=' and peek(2) != '=':
                take(); take(); typ()
            elif peek() == '{':
                take(); until_close('{', '}')
            else:
                out.append(typ())
            if peek() == ',': take()
        if peek() == '>': take()
        return out

    def typ():
        token = peek()
        if token is None: return ('raw', text)
        if token == '&':
            take()
            if peek() and peek().startswith("'"): take()
            if peek() == 'mut': take()
            return ('ref', typ())
        if token == '(':
            take(); items = []
            while peek() not in (')', None):
                items.append(typ())
                if peek() == ',': take()
            take()
            return ('tuple', items)
        if token == '[':
            take(); item = typ()
            if peek() == ';':
                take()
                while peek() not in (']', None):
                    if take() in '([{': until_close('[', ']')
            take()
            return ('array', item)
        if token in ('dyn', 'impl', 'fn', '*', '<', '!', '_'):
            return ('raw', text)
        segments, generic = [], []
        if token == '::': take()
        while True:
            name = take()
            if name is None or not re.match(r'(r#)?[A-Za-z_]\w*$', name):
                return ('raw', text)
            segments.append(name.removeprefix('r#'))
            if peek() == '::' and peek(1) == '<':
                take()
            if peek() == '<':
                take(); generic = args()
            if peek() == '::' and peek(1) and re.match(r'[A-Za-z_]', peek(1)):
                take(); continue
            break
        return ('path', segments, generic)

    result = typ()
    return result if position >= len(tokens) else ('raw', text)


# ---------------------------------------------------------------- the index

class Item:
    __slots__ = ('crate', 'file', 'module', 'name', 'kind', 'top', 'attrs', 'generics', 'body', 'shape', 'uses')

    def key(self):
        return (self.crate, self.file, self.name, self.module)


class Index:
    'Every struct, enum and alias of the engine crates, with each file\'s imports.'

    HEADER = re.compile(r'(?m)^([ \t]*)(pub(?:\s*\([^)]*\))?\s+)?(struct|enum|type)\s+([A-Za-z_]\w*)')
    IMPL = re.compile(r'(?m)^[ \t]*impl\b[^{;]*?\b(?:serde::)?Serialize\s+for\s+([A-Za-z_]\w*)')
    DE_IMPL = re.compile(r"(?m)^[ \t]*impl\b[^{;]*?\b(?:serde::)?Deserialize<'de>\s+for\s+([A-Za-z_]\w*)")
    # `some_macro!(Name, ...)`: a type a macro defines.
    MACRO_USE = re.compile(r'(?m)^[ \t]*(?:pub\s+)?(\w+)!\s*[({]\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct\s+)?([A-Z]\w*)\b')

    def __init__(self, root):
        self.root = Path(root)
        self.loaded = set()
        self.items = {}       # name -> [Item]
        self.files = {}       # (crate, file) -> text
        self.modules = {}     # (crate, module tuple) -> file
        self.impls = {}       # name -> [(crate, file, position)]
        self.de_impls = {}
        self.macro_uses = {}  # type name -> [(crate, file, macro)]
        self.macros = {}      # macro name -> its macro_rules text
        self.use_cache = {}
        self.guesses = set()
        for crate in EAGER: self.load(crate)

    def load(self, crate):
        if crate in self.loaded or crate not in CRATES: return
        self.loaded.add(crate)
        base = self.root / CRATES[crate]
        for path in sorted(base.rglob('*.rs')):
            relative = path.relative_to(base).as_posix()
            if '/tests/' in '/' + relative or relative.endswith(('_tests.rs', '/tests.rs')) or relative == 'tests.rs':
                continue
            text = path.read_text(errors='replace')
            self.files[(crate, relative)] = text
            parts = relative[:-3].split('/')
            if parts[-1] in ('mod', 'lib', 'main'): parts = parts[:-1]
            self.modules.setdefault((crate, tuple(parts)), relative)
            for match in self.HEADER.finditer(text):
                indent, public, kind, name = match.groups()
                if kind == 'type' and not public and indent: continue
                item = self.read_item(crate, relative, tuple(parts), text, match)
                if item: self.items.setdefault(name, []).append(item)
            for match in self.IMPL.finditer(text):
                self.impls.setdefault(match.group(1), []).append((crate, relative, match.start()))
            for match in self.DE_IMPL.finditer(text):
                self.de_impls.setdefault(match.group(1), []).append((crate, relative, match.start()))
            if 'macro_rules!' in text or '!(' in text:
                for match in self.MACRO_USE.finditer(text):
                    if match.group(1) != 'macro_rules':
                        self.macro_uses.setdefault(match.group(2), []).append((crate, relative, match.group(1)))
                for match in re.finditer(r'macro_rules!\s*(\w+)\s*\{', text):
                    self.macros[match.group(1)] = text[match.start():close_of(text, match.end() - 1)]

    def read_item(self, crate, file, module, text, match):
        indent, _, kind, name = match.groups()
        item = Item()
        item.crate, item.file, item.module, item.name, item.kind, item.top = crate, file, module, name, kind, not indent
        # The attributes: the lines above the header back to the previous item.
        lines, start = [], match.start()
        while start > 0:
            line_start = text.rfind('\n', 0, start - 1) + 1
            line = text[line_start:start].strip()
            if not line or line.endswith(('}', ';', '{')) and not line.startswith(('#', '//')):
                break
            if not line.startswith('//'): lines.append(line)
            start = line_start
        item.attrs = ' '.join(reversed(lines))
        position = match.end()
        item.generics = []
        rest = text[position:position + 4]
        if rest.lstrip().startswith('<'):
            position = text.index('<', position)
            depth, end = 0, position
            while end < len(text):
                if text.startswith('->', end): end += 2; continue
                depth += text[end] == '<'; depth -= text[end] == '>'
                end += 1
                if depth == 0: break
            for param in split_top(text[position + 1:end - 1]):
                param = param.strip()
                if param.startswith("'") or param.startswith('const '): continue
                item.generics.append(re.match(r'\w+', param).group(0))
            position = end
        if kind == 'type':
            equals = text.find('=', position)
            semi = equals
            while semi < len(text) and text[semi] != ';':
                j = _skip(text, semi)
                semi = close_of(text, semi) if text[semi] in '([{' else (j if j != semi else semi + 1)
            item.body, item.shape = text[equals + 1:semi].strip(), 'alias'
            return item
        # The body opens at the first `{`, `(` or `;` past any where clause.
        search = re.compile(r'[{(;]')
        found = search.search(text, position)
        if not found: return None
        opener = found.group(0)
        if opener == ';':
            item.body, item.shape = '', 'unit'
        else:
            end = close_of(text, found.start())
            item.body = strip_comments(text[found.start() + 1:end - 1])
            item.shape = 'named' if opener == '{' else 'tuple'
        return item

    # ---- resolution

    def uses(self, crate, file):
        'The file\'s imports: alias -> path, and its glob paths.'
        key = (crate, file)
        if key in self.use_cache: return self.use_cache[key]
        names, globs = {}, []
        text = self.files.get(key, '')
        for match in re.finditer(r'(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);', text):
            for alias, path in self.expand_use([], strip_comments(match.group(1))):
                if alias == '*': globs.append(path)
                else: names.setdefault(alias, path)
        self.use_cache[key] = (names, globs)
        return names, globs

    def expand_use(self, prefix, tree):
        tree = tree.strip().lstrip(':')
        if tree.endswith('}'):
            brace = tree.index('{')
            head = [s for s in tree[:brace].split('::') if s.strip()]
            out = []
            for part in split_top(tree[brace + 1:-1]):
                out += self.expand_use(prefix + [s.strip() for s in head], part)
            return out
        if tree.endswith('*'):
            return [('*', prefix + [s.strip() for s in tree[:-1].split('::') if s.strip()])]
        alias = None
        if ' as ' in tree:
            tree, alias = [s.strip() for s in tree.split(' as ', 1)]
        segments = prefix + [s.strip() for s in tree.split('::') if s.strip()]
        if segments and segments[-1] == 'self': segments = segments[:-1]
        if not segments or alias == '_': return []
        return [(alias or segments[-1], segments)]

    def absolute(self, segments, crate, module):
        'A path\'s crate and module segments, from a file in (crate, module); None for an external crate.'
        head = segments[0]
        if head == 'crate': return crate, list(segments[1:])
        if head == 'self': return crate, list(module) + list(segments[1:])
        if head == 'super':
            up = 0
            while up < len(segments) and segments[up] == 'super': up += 1
            return crate, list(module[:max(0, len(module) - up)]) + list(segments[up:])
        if head in CRATES:
            self.load(head)
            return head, list(segments[1:])
        if head in EXTERNAL: return None
        return crate, list(module) + list(segments)

    def resolve(self, segments, crate, file, module, depth=0):
        'The item a path names from a file: an Item, ("external", name) or None.'
        if depth > 12: return None
        if len(segments) == 1: return self.resolve_name(segments[0], crate, file, module, depth)
        head = segments[0]
        if head not in ('crate', 'self', 'super') and head not in CRATES:
            names, _ = self.uses(crate, file)
            if head in names:
                return self.resolve(names[head] + list(segments[1:]), crate, file, module, depth + 1)
        place = self.absolute(segments, crate, module)
        if place is None: return ('external', segments[-1])
        target_crate, path = place
        return self.resolve_in(target_crate, tuple(path[:-1]), path[-1], depth + 1)

    def resolve_in(self, crate, module, name, depth):
        if depth > 12: return None
        file = self.modules.get((crate, module))
        if file is not None:
            local = [item for item in self.items.get(name, ()) if item.crate == crate and item.file == file]
            if local: return min(local, key=lambda item: not item.top)
            names, globs = self.uses(crate, file)
            if name in names:
                found = self.resolve(names[name], crate, file, module, depth + 1)
                if found: return found
            for glob in globs:
                place = self.absolute(glob, crate, module)
                if place is None: continue
                found = self.resolve_in(place[0], tuple(place[1]), name, depth + 1)
                if found: return found
        return self.by_name(name, crate, module, within=module)

    def resolve_name(self, name, crate, file, module, depth=0):
        local = [item for item in self.items.get(name, ()) if item.crate == crate and item.file == file]
        if local: return min(local, key=lambda item: not item.top)
        names, globs = self.uses(crate, file)
        if name in names:
            found = self.resolve(names[name], crate, file, module, depth + 1)
            if found: return found
        for glob in globs:
            place = self.absolute(glob, crate, module)
            if place is None: continue
            found = self.resolve_in(place[0], tuple(place[1]), name, depth + 1)
            if found and not (isinstance(found, tuple)): return found
        return self.by_name(name, crate, module)

    def macro_token(self, name):
        'A type a macro defines: a string when the macro writes it with `serialize_str`.'
        for _, _, macro in self.macro_uses.get(name, ()):
            body = self.macros.get(macro, '')
            if re.search(r'serialize_str|collect_str', body): return STRING
        return None

    def by_name(self, name, crate, module, within=None):
        'The best candidate of that name: same crate, under `within`, nearest module.'
        candidates = [item for item in self.items.get(name, ()) if item.kind != 'type' or item.top]
        if within is not None:
            under = [item for item in candidates if item.crate == crate and item.module[:len(within)] == tuple(within)]
            if under: candidates = under
        if not candidates: return None
        if len({(item.crate, item.file) for item in candidates}) > 1: self.guesses.add(name)
        def rank(item):
            common = 0
            for a, b in zip(item.module, module):
                if a != b: break
                common += 1
            return (item.crate != crate, not item.top, -common, len(item.module), item.file)
        return min(candidates, key=rank)


# ---------------------------------------------------------------- inventory

class Inventory:
    'The declarations every facade root reaches, and the census of what they read as.'

    def __init__(self, root, rows):
        self.index = Index(root)
        self.decls = {}       # item key -> declaration dict
        self.order = []
        self.names = set()
        self.fallbacks = []   # (declaration, rust text, reason)
        self.opaques = []     # (declaration, rust text): serde_json values, opaque by design
        # What a typed binding needs past the wire shape: each derived enum's
        # serde tagging and variants, by declaration name, and each named
        # field a writer must send as `null` rather than omit (an `Option`
        # under a field codec with no `default`), by (owner, key), and each
        # declaration that refuses unknown fields.
        self.variants = {}
        self.null_fields = set()
        self.closed = set()
        self.roots = {}       # rust text -> IR
        crate, file = ROOT_CONTEXT
        file = file[len(CRATES[crate]) + 1:]
        self.root_context = (crate, file, tuple(file[:-3].split('/')))
        for row in rows:
            for text in (row['input'], row['output']):
                self.root_ir(text)

    def root_ir(self, text):
        'A row type, named as the SDK module names it.'
        if text not in self.roots:
            self.roots[text] = self.ir(parse_type(text), self.root_context, (), text)
        return self.roots[text]

    def ts_type(self, text, prefix='Facade.'):
        'A row type as TypeScript spells it outside the declarations module.'
        return self.ts(self.root_ir(text), prefix)

    def py_type(self, text, prefix='Facade.'):
        'A row type as the Python stubs spell it outside the declarations module.'
        return self._py_outer(self.root_ir(text), prefix)

    # ---- naming

    def allocate(self, item):
        name = item.name
        if name in self.names or name in RESERVED:
            for size in range(1, len(item.module) + 1):
                prefix = ''.join(part.title().replace('_', '') for part in item.module[-size:])
                if prefix + name not in self.names and prefix + name not in RESERVED:
                    name = prefix + name; break
            else:
                base, n = name, 2
                while name in self.names or name in RESERVED:
                    name = f'{base}{n}'; n += 1
        self.names.add(name)
        return name

    def declare(self, item):
        key = item.key()
        if key not in self.decls:
            decl = {'name': self.allocate(item), 'params': list(item.generics), 'item': item, 'ir': None}
            self.decls[key] = decl
            decl['ir'] = self.item_ir(item, decl)
            self.order.append(key)
        return self.decls[key]

    def fallback(self, where, text, reason):
        self.fallbacks.append((where, text.strip(), reason))
        return ('unknown', reason)

    # ---- Rust type -> IR

    def ir(self, ast, context, params, where):
        crate, file, module = context
        kind = ast[0]
        if kind == 'ref': return self.ir(ast[1], context, params, where)
        if kind == 'tuple':
            return NULL if not ast[1] else ('tuple', [self.ir(a, context, params, where) for a in ast[1]])
        if kind == 'array':
            return ('array', self.ir(ast[1], context, params, where))
        if kind == 'raw': return self.fallback(where, ast[1], 'unparseable type')
        segments, args = ast[1], ast[2]
        name = segments[-1]
        if len(segments) == 1 and name in params: return ('param', name)
        external = segments[0] in EXTERNAL
        resolved = None
        if not external and not (len(segments) == 1 and name in PRELUDE):
            resolved = self.index.resolve(segments, crate, file, module)
            if isinstance(resolved, tuple): external, name, resolved = True, resolved[1], None
        if resolved is None:
            # A std or external type by its conventional wire spelling; a
            # crate type the index cannot find is never guessed into one.
            conventional = external or name in PRELUDE or name in WRAPPERS or name in SEQUENCES or name in MAPS
            leaf = self.std(name, args, context, params, where) if conventional else None
            if leaf is not None:
                if leaf is OPAQUE: self.opaques.append((where, '::'.join(segments)))
                return leaf
            token = self.index.macro_token(name) if not external else None
            if token is not None: return token
            return self.fallback(where, '::'.join(segments), 'external type' if external else 'unresolved type')
        decl = self.declare(resolved)
        arguments = [self.ir(a, context, params, where) for a in args][:len(decl['params'])]
        while len(arguments) < len(decl['params']): arguments.append(('unknown', 'missing type argument'))
        return ('ref', resolved.key(), arguments)

    def std(self, name, args, context, params, where):
        'A std or external type the wire spells by convention, or None.'
        inner = [self.ir(a, context, params, where) for a in args]
        if name == 'Option' and inner: return ('option', inner[0])
        if name in WRAPPERS and inner: return inner[0]
        if name in ('Bytes', 'ByteBuf'): return ('array', width('u8'))
        if name in SEQUENCES and inner: return ('array', inner[0])
        if name in MAPS:
            if len(inner) > 1: return ('map', inner[1])
            self.opaques.append((where, name))
            return ('map', OPAQUE)
        if name == 'Result' and len(inner) == 2:
            return ('union', [('object', [('Ok', inner[0], False)], 'Ok'), ('object', [('Err', inner[1], False)], 'Err')])
        if name in LEAVES: return LEAVES[name]
        return None

    def codec(self, ast, codec, context, params, where):
        'A field under `with = codec`: id, hex, digest and base64 codecs put a string on the wire.'
        leaf = codec.rsplit('::', 1)[-1]
        if re.search(r'limited|bounded|capped', codec): return self.ir(ast, context, params, where)
        stringy = re.search(r'entit|ref|_id|id_|^id$|::id$|hex|digest|base64|b64|hash|blake|uuid|display', codec + '::' + leaf)
        if not stringy:
            return self.fallback(where, codec, 'field codec')
        def walk(node):
            if node[0] == 'path':
                name = node[1][-1]
                if name == 'Option' and node[2]: return ('option', walk(node[2][0]))
                if name in SEQUENCES - {'Bytes', 'ByteBuf'} and node[2] and not (node[2][0][0] == 'path' and node[2][0][1][-1] == 'u8'):
                    return ('array', walk(node[2][0]))
                if name in MAPS and len(node[2]) > 1: return ('map', walk(node[2][1]))
            if node[0] == 'ref': return walk(node[1])
            return STRING
        return walk(ast)

    def field_ir(self, typ, attrs, context, params, where):
        schema = attr_args(attrs, 'schemars')
        serde = attr_args(attrs, 'serde')
        ast = parse_type(typ)
        codec = serde.get('with') or serde.get('serialize_with')
        mark = len(self.fallbacks)
        value = self.codec(ast, codec, context, params, where) if isinstance(codec, str) else self.ir(ast, context, params, where)
        # The schema's own spelling of a field stands in only where the
        # serde type could not be read.
        if len(self.fallbacks) > mark and isinstance(schema.get('with'), str):
            del self.fallbacks[mark:]
            return self.ir(parse_type(schema['with']), context, params, where)
        return value

    def fields(self, body, case, container_default, context, params, where):
        'Named fields as ([(key, IR, optional)], [flattened IR]).'
        out, flat = [], []
        for chunk in split_top(body):
            attrs, rest = leading_attrs(chunk)
            match = re.match(r'(?:pub(?:\s*\([^)]*\))?\s+)?(r#)?(\w+)\s*:\s*(.+)$', rest, re.S)
            if not match: continue
            name, typ = match.group(2), match.group(3).strip()
            serde = attr_args(attrs, 'serde')
            if serde.get('skip') or (serde.get('skip_serializing') and serde.get('skip_deserializing')): continue
            value = self.field_ir(typ, attrs, context, params, f'{where}.{name}')
            if serde.get('flatten'):
                flat.append(('partial', value[1]) if value[0] == 'option' else value); continue
            key = serialize_case(serde.get('rename')) or rename(name, case, False)
            optional = (value[0] == 'option' or 'default' in serde or container_default or 'skip_serializing_if' in serde
                        or serde.get('skip_serializing') is True or serde.get('skip_deserializing') is True)
            if value[0] == 'option' and isinstance(codec_of(serde), str) and 'default' not in serde and not container_default:
                self.null_fields.add((where, key))
            out.append((key, value, optional))
        return out, flat

    def object(self, body, case, container_default, context, params, where, hint=None, extra=()):
        fields, flat = self.fields(body, case, container_default, context, params, where)
        record = ('object', list(extra) + fields, hint)
        return ('and', flat + [record]) if flat else record

    def tuple_fields(self, body, context, params, where):
        out = []
        for n, chunk in enumerate(split_top(body)):
            attrs, rest = leading_attrs(chunk)
            rest = re.sub(r'^pub(?:\s*\([^)]*\))?\s+', '', rest)
            if attr_args(attrs, 'serde').get('skip'): continue
            out.append(self.field_ir(rest, attrs, context, params, f'{where}.{n}'))
        return out

    def item_ir(self, item, decl):
        context = (item.crate, item.file, item.module)
        params = tuple(item.generics)
        where = decl['name']
        if item.kind == 'type':
            return self.ir(parse_type(item.body), context, params, where)
        serde = attr_args(item.attrs, 'serde')
        derived = derives(item.attrs)
        # What the type writes: its `into` type, else its own derive; a type
        # that only reads takes the shape it reads `from`.
        conversions = ('into',) if 'Serialize' in derived else ('into', 'try_from', 'from')
        for key in conversions:
            if isinstance(serde.get(key), str):
                return self.ir(parse_type(serde[key]), context, params, where)
        if not derived & {'Serialize', 'Deserialize'}:
            return self.manual(item, context, params, where)
        if derived & {'Serialize_repr', 'Deserialize_repr'}:
            repr_ = re.search(r'\brepr\s*\(\s*([ui](?:8|16|32|64|size))\b', item.attrs)
            return width(repr_.group(1)) if repr_ else INT
        case = serialize_case(serde.get('rename_all'))
        default = serde.get('default') is True or isinstance(serde.get('default'), str)
        if serde.get('deny_unknown_fields') is True: self.closed.add(where)
        if item.kind == 'struct':
            if item.shape == 'unit': return NULL
            if item.shape == 'tuple':
                values = self.tuple_fields(item.body, context, params, where)
                if len(values) == 1: return values[0]
                return ('tuple', values)
            if serde.get('transparent'):
                fields, flat = self.fields(item.body, None, False, context, params, where)
                return fields[0][1] if fields else (flat[0] if flat else NULL)
            tag = serde.get('tag')
            extra = [(tag, ('lit', serialize_case(serde.get('rename')) or item.name), False)] if isinstance(tag, str) else []
            return self.object(item.body, case, default, context, params, where, extra=extra)
        return self.enum(item, serde, case, context, params, where)

    def enum(self, item, serde, case, context, params, where):
        tag, content = serde.get('tag'), serde.get('content')
        untagged = serde.get('untagged') is True
        field_case = serialize_case(serde.get('rename_all_fields'))
        members, variants = [], []
        for chunk in split_top(item.body):
            attrs, rest = leading_attrs(chunk)
            match = re.match(r'(\w+)\s*(.*)$', rest, re.S)
            if not match: continue
            name, payload = match.group(1), match.group(2).strip()
            variant = attr_args(attrs, 'serde')
            if variant.get('skip') or variant.get('skip_serializing') and variant.get('skip_deserializing'): continue
            label = serialize_case(variant.get('rename')) or rename(name, case, True)
            inner_case = serialize_case(variant.get('rename_all')) or field_case
            at = f'{where}.{name}'
            if payload.startswith('{'):
                body = payload[1:close_of(payload, 0) - 1]
                shape, value = 'struct', None
            elif payload.startswith('('):
                body = payload[1:close_of(payload, 0) - 1]
                values = self.tuple_fields(body, context, params, at)
                shape, value = ('newtype', values[0]) if len(values) == 1 else ('tuple', ('tuple', values))
            else:
                shape, value = 'unit', None
            if untagged or variant.get('untagged'):
                if shape == 'unit': members.append(NULL)
                elif shape == 'struct': members.append(self.object(body, inner_case, False, context, params, at, name))
                else: members.append(value)
            elif isinstance(tag, str) and isinstance(content, str):
                fields = [(tag, ('lit', label), False)]
                if shape == 'struct': fields.append((content, self.object(body, inner_case, False, context, params, at, name + 'Content'), False))
                elif shape != 'unit': fields.append((content, value, False))
                members.append(('object', fields, name))
            elif isinstance(tag, str):
                marker = (tag, ('lit', label), False)
                if shape == 'struct': members.append(self.object(body, inner_case, False, context, params, at, name, extra=[marker]))
                elif shape == 'unit': members.append(('object', [marker], name))
                else: members.append(('and', [value, ('object', [marker], name)]))
            else:
                if shape == 'unit': members.append(('lit', label))
                elif shape == 'struct':
                    members.append(('object', [(label, self.object(body, inner_case, False, context, params, at, name + 'Body'), False)], name))
                else: members.append(('object', [(label, value, False)], name))
            variants.append({'name': name, 'label': label, 'untagged': bool(untagged or variant.get('untagged')),
                             'other': variant.get('other') is True, 'shape': shape, 'member': members[-1]})
        self.variants[where] = {'tag': tag if isinstance(tag, str) else None, 'content': content if isinstance(content, str) else None,
                                'untagged': untagged, 'variants': variants}
        if not members: return ('never',)
        return members[0] if len(members) == 1 else ('union', members)

    def manual(self, item, context, params, where):
        'A type with a handwritten `Serialize`: what its serializer writes, when that is plain.'
        impls = [(c, f, p) for c, f, p in self.index.impls.get(item.name, ()) if c == item.crate] or self.index.impls.get(item.name, [])
        for crate, file, position in impls:
            text = self.index.files[(crate, file)]
            body = text[position:close_of(text, text.index('{', position))]
            if re.search(r'serialize_str|collect_str|to_string\(\)\.serialize|as_str\(\)\.serialize|to_hex\(\)\.serialize', body): return STRING
            written = re.search(r'serialize_([ui]\d+|usize)', body)
            if written: return width(written.group(1))
            if re.search(r'serialize_f\d+', body): return FLOAT
            if re.search(r'serialize_bool', body): return BOOL
            if item.shape == 'tuple' and re.search(r'self\.0\.serialize\(', body):
                values = self.tuple_fields(item.body, context, params, where)
                if values: return values[0]
            # A handwritten pair that reads a wire mirror writes that mirror.
            for crate2, file2, position2 in self.index.de_impls.get(item.name, ()):
                text2 = self.index.files[(crate2, file2)]
                body2 = text2[position2:close_of(text2, text2.index('{', position2))]
                mirror = re.search(r'(?:<\s*)?([A-Z]\w*)(?:\s+as\s+[\w:]*Deserialize[^>]*>)?::deserialize\(\s*deserializer', body2)
                if mirror and mirror.group(1) not in ('Self', item.name, 'String'):
                    return self.ir(parse_type(mirror.group(1)), (crate2, file2, item.module), params, where)
            return self.fallback(where, item.name, 'handwritten Serialize')
        if item.shape == 'tuple' and item.kind == 'struct':
            schema = attr_args(item.body, 'schemars')
            if isinstance(schema.get('with'), str): return self.ir(parse_type(schema['with']), context, params, where)
        return self.fallback(where, item.name, 'no serde derive')

    # ---- census

    def reach(self, value, seen):
        'Fallback and opaque counts reachable from an IR value.'
        unknown, opaque = 0, 0
        stack = [value]
        while stack:
            node = stack.pop()
            kind = node[0]
            if kind == 'unknown': unknown += 1
            elif kind == 'opaque': opaque += 1
            elif kind in ('array', 'option', 'map'): stack.append(node[1])
            elif kind in ('tuple', 'union', 'and'): stack.extend(node[1])
            elif kind == 'object': stack.extend(field[1] for field in node[1])
            elif kind == 'partial': stack.append(node[1])
            elif kind == 'ref':
                stack.extend(node[2])
                if node[1] not in seen:
                    seen.add(node[1]); stack.append(self.decls[node[1]]['ir'])
        return unknown, opaque

    def root_state(self, text):
        unknown, opaque = self.reach(self.root_ir(text), set())
        return 'unknown' if unknown else 'opaque' if opaque else 'typed'

    def census(self, rows):
        'How the rows\' inputs and results read: fully typed, typed to an opaque leaf, or with an unread shape.'
        states = {'input': {}, 'output': {}}
        for row in rows:
            for side in states:
                state = self.root_state(row[side])
                states[side][state] = states[side].get(state, 0) + 1
        def side(name, label):
            counts = states[name]
            return (f'{label}: {counts.get("typed", 0)} of {len(rows)} fully typed, {counts.get("opaque", 0)} typed down to an '
                    f'opaque serde_json::Value leaf, {counts.get("unknown", 0)} with a shape the generator could not read')
        return [
            f'Census: {len(rows)} facade rows, {len(self.decls)} declarations.',
            side('input', 'Inputs'),
            side('output', 'Results'),
            f'Opaque serde_json::Value leaves: {len(self.opaques)}; unread shapes: {len(self.fallbacks)}.',
        ]

    # ---- TypeScript

    def ts(self, node, prefix=''):
        kind = node[0]
        if kind == 'prim': return {'string': 'string', 'int': 'number', 'float': 'number', 'bool': 'boolean', 'null': 'null'}[node[1]]
        if kind in ('unknown', 'opaque'): return 'unknown'
        if kind == 'never': return 'never'
        if kind == 'lit': return json.dumps(node[1])
        if kind == 'param': return node[1]
        if kind == 'array':
            inner = self.ts(node[1], prefix)
            return f'({inner})[]' if compound(inner) else inner + '[]'
        if kind == 'option':
            inner = self.ts(node[1], prefix)
            return inner if inner.endswith('| null') or inner == 'null' else inner + ' | null'
        if kind == 'tuple': return '[' + ', '.join(self.ts(t, prefix) for t in node[1]) + ']'
        if kind == 'map': return 'Record<string, ' + self.ts(node[1], prefix) + '>'
        if kind == 'union':
            parts = []
            for member in node[1]:
                text = self.ts(member, prefix)
                if text not in parts: parts.append(text)
            return ' | '.join(f'({p})' if compound(p, '&') else p for p in parts)
        if kind == 'and':
            parts = [self.ts(member, prefix) for member in node[1]]
            return ' & '.join(f'({p})' if compound(p, '|') else p for p in parts)
        if kind == 'partial': return 'Partial<' + self.ts(node[1], prefix) + '>'
        if kind == 'object':
            if not node[1]: return 'Record<string, never>'
            return '{ ' + '; '.join(ts_key(key) + ('?' if optional else '') + ': ' + self.ts(value, prefix) for key, value, optional in node[1]) + ' }'
        if kind == 'ref':
            decl = self.decls[node[1]]
            args = '<' + ', '.join(self.ts(a, prefix) for a in node[2]) + '>' if node[2] else ''
            return prefix + decl['name'] + args
        raise ValueError(node)

    def typescript(self, census_lines):
        out = '// Generated by scripts/sdk/generate.py from the Rust types each facade row\n'
        out += '// of scripts/sdk/agent-verbs.json names; edit the Rust types or the table.\n'
        out += ''.join('// ' + line + '\n' for line in census_lines)
        for key in self.order:
            decl = self.decls[key]
            params = '<' + ', '.join(decl['params']) + '>' if decl['params'] else ''
            item = decl['item']
            out += '/** `' + '::'.join((item.crate,) + item.module + (item.name,)) + '` */\n'
            out += f'export type {decl["name"]}{params} = {self.ts(decl["ir"])}\n'
        return out

    # ---- Python

    def python(self, census_lines):
        hoisted, typevars = [], set()
        names = set(decl['name'] for decl in self.decls.values())

        def fresh(base):
            name, n = base, 2
            while name in names or name in RESERVED:
                name = f'{base}{n}'; n += 1
            names.add(name)
            return name

        def py(node, owner):
            kind = node[0]
            if kind == 'prim': return {'string': 'str', 'int': 'int', 'float': 'float', 'bool': 'bool', 'null': 'None'}[node[1]]
            if kind in ('unknown', 'opaque', 'never'): return 'Any'
            if kind == 'lit': return 'Literal[' + json.dumps(node[1]) + ']'
            if kind == 'param':
                typevars.add(node[1]); return node[1]
            if kind == 'array': return 'list[' + py(node[1], owner) + ']'
            if kind == 'option':
                inner = py(node[1], owner)
                return inner if inner.endswith('| None') or inner == 'None' else inner + ' | None'
            if kind == 'tuple': return 'tuple[' + ', '.join(py(t, owner) for t in node[1]) + ']'
            if kind == 'map': return 'dict[str, ' + py(node[1], owner) + ']'
            if kind == 'union':
                parts, literals = [], []
                for member in node[1]:
                    if member[0] == 'lit': literals.append(json.dumps(member[1])); continue
                    text = py(member, owner)
                    if text not in parts: parts.append(text)
                if literals: parts.insert(0, 'Literal[' + ', '.join(literals) + ']')
                return ' | '.join(parts)
            if kind == 'partial': return py(node[1], owner)
            if kind in ('object', 'and'):
                hint = node[2] if kind == 'object' else next((m[2] for m in node[1] if m[0] == 'object'), None)
                name = fresh(owner + (hint or 'Item'))
                # A variant of a generic type is generic over the parameters it uses.
                used = sorted(type_params(node))
                klass(name, node, used, owner)
                return name + ('[' + ', '.join(used) + ']' if used else '')
            if kind == 'ref':
                decl = self.decls[node[1]]
                args = '[' + ', '.join(py(a, owner) for a in node[2]) + ']' if node[2] else ''
                return decl['name'] + args
            raise ValueError(node)

        def klass(name, node, params, owner):
            'A TypedDict for an object (or an intersection of objects), or an alias when a dict cannot say it.'
            members = node[1] if node[0] == 'and' else [node]
            bases, fields = [], []
            for member in members:
                if member[0] == 'object': fields += member[1]
                elif member[0] == 'partial' and member[1][0] == 'ref' and self.is_record(member[1]): bases.append(py(member[1], owner))
                elif member[0] == 'ref' and self.is_record(member): bases.append(py(member, owner))
                else:
                    hoisted.append(f'{name} = dict[str, Any]\n'); return
            generic = ', Generic[' + ', '.join(params) + ']' if params else ''
            rows = []
            for key, value, optional in fields:
                text = py(value, owner)
                rows.append((key, f'NotRequired[{text}]' if optional else text))
            if any(not key.isidentifier() or keyword.iskeyword(key) for key, _ in rows):
                if bases or params:
                    hoisted.append(f'{name} = dict[str, Any]\n'); return
                body = ', '.join(json.dumps(key) + ': ' + text for key, text in rows)
                hoisted.append(f'{name} = TypedDict({json.dumps(name)}, {{{body}}})\n'); return
            head = f'class {name}(' + ', '.join(bases or ['TypedDict']) + generic + '):\n'
            hoisted.append(head + (''.join(f'    {key}: {text}\n' for key, text in rows) or '    ...\n'))

        for key in self.order:
            decl = self.decls[key]
            node = decl['ir']
            typevars.update(decl['params'])
            if node[0] in ('object', 'and') and (node[0] == 'object' or all(m[0] in ('object', 'ref', 'partial') for m in node[1])):
                klass(decl['name'], node, decl['params'], decl['name'])
            else:
                hoisted.append(f'{decl["name"]} = {py(node, decl["name"])}\n')
        out = '"""Generated by scripts/sdk/generate.py from the Rust types each facade row of\n'
        out += 'scripts/sdk/agent-verbs.json names; edit the Rust types or the table.\n\n'
        out += 'Keys are the engine\'s own wire spelling. Shapes the generator could not read\n'
        out += 'are `Any`, and the census below counts them.\n\n'
        out += ''.join(line + '\n' for line in census_lines) + '"""\n\n'
        out += 'from typing import Any, Generic, Literal, NotRequired, TypedDict, TypeVar\n\n'
        out += ''.join(f'{name} = TypeVar({json.dumps(name)})\n' for name in sorted(typevars))
        out += '\n' + ''.join(hoisted)
        return out

    def is_record(self, node):
        'Whether a reference names a declaration Python spells as a TypedDict class.'
        if node[0] == 'partial': node = node[1]
        if node[0] != 'ref': return False
        ir = self.decls[node[1]]['ir']
        return ir[0] == 'object' or ir[0] == 'and' and all(m[0] in ('object', 'ref', 'partial') for m in ir[1]) and all(self.is_record(m) for m in ir[1] if m[0] != 'object')

    def _py_outer(self, node, prefix):
        kind = node[0]
        if kind == 'prim': return {'string': 'str', 'int': 'int', 'float': 'float', 'bool': 'bool', 'null': 'None'}[node[1]]
        if kind in ('unknown', 'opaque', 'never'): return 'Any'
        if kind == 'array': return 'list[' + self._py_outer(node[1], prefix) + ']'
        if kind == 'option': return self._py_outer(node[1], prefix) + ' | None'
        if kind == 'map': return 'dict[str, ' + self._py_outer(node[1], prefix) + ']'
        if kind == 'tuple': return 'tuple[' + ', '.join(self._py_outer(t, prefix) for t in node[1]) + ']'
        if kind == 'union': return ' | '.join(self._py_outer(t, prefix) for t in node[1])
        if kind == 'lit': return 'Literal[' + json.dumps(node[1]) + ']'
        if kind == 'ref':
            decl = self.decls[node[1]]
            args = '[' + ', '.join(self._py_outer(a, prefix) for a in node[2]) + ']' if node[2] else ''
            return prefix + decl['name'] + args
        return 'dict[str, Any]'


def ts_key(key):
    return key if re.fullmatch(r'[A-Za-z_$][\w$]*', key) else json.dumps(key)


def compound(text, operators='|&'):
    'Whether a TypeScript type has a top-level union or intersection.'
    depth = 0
    for n, c in enumerate(text):
        if c in '{[(<': depth += 1
        elif c in '}])>': depth -= 1
        elif depth == 0 and c in operators and text[n - 1:n + 2] == f' {c} ': return True
    return False


def type_params(node):
    'The generic parameters an IR value names.'
    found, stack = set(), [node]
    while stack:
        item = stack.pop()
        kind = item[0]
        if kind == 'param': found.add(item[1])
        elif kind in ('array', 'option', 'map', 'partial'): stack.append(item[1])
        elif kind in ('tuple', 'union', 'and'): stack.extend(item[1])
        elif kind == 'object': stack.extend(field[1] for field in item[1])
        elif kind == 'ref': stack.extend(item[2])
    return found
