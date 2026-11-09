//! Port of facade_types.py:697-1008 (the `Rust type -> IR` section of `Inventory`): a Rust type, field, struct or
//! enum as its serde wire shape.

use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;

use super::super::index::{Found, ItemRef, Kind, Shape, declared_names, deserialize_fn_end};
use super::super::reader::{
    Ast, attr_args, case_or, close_of, codec_of, derives, find_from, is_true, leading_attrs,
    or_value, parse_type, prev_char, rename, search_bounded, serialize_case, slice, split_top,
    truthy,
};
use super::super::{
    EXTERNAL, Field, INT, Ir, MAPS, NULL, PRELUDE, SEQUENCES, STRING, WRAPPERS, byte_id_codec,
    holds, index_error, leaf, substring_not_found, width,
};
use super::{Context, EnumMeta, Inventory, VariantMeta, VariantShape};
use crate::error::GenerateError;
use crate::py::re::compile;
use crate::py::text::{strip, title};
use crate::py::value::{Dict, Value};

/// facade_types.py:751: `limited|bounded|capped`
static BOUNDED: LazyLock<Regex> = LazyLock::new(|| compile("limited|bounded|capped"));
/// facade_types.py:758: `entit|ref|_id|id_|^id$|::id$|hex|digest|base64|b64|hash|blake|uuid|display|decimal`
/// (Python's `^` is the start, its `$` the end or before a final newline).
static STRINGY: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"entit|ref|_id|id_|\Aid\n?\z|::id\n?\z|hex|digest|base64|b64|hash|blake|uuid|display|decimal",
    )
});
/// facade_types.py:811, the mirror a codec's `deserialize` reads.
static CODEC_READ: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?:<\s*)?((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:::<[^;{}()]*?>)?)(?:\s+as\s+[\w:]*Deserialize[^>]*>)?::deserialize\(\s*deserializer",
    )
});
/// facade_types.py:834: `re.match(r'(?:pub(?:\s*\([^)]*\))?\s+)?(r#)?(\w+)\s*:\s*(.+)$', rest, re.S)`; greedy `.+`
/// runs to the end, so `$` holds there.
static FIELD: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)\A(?:pub(?:\s*\([^)]*\))?\s+)?(r#)?(\w+)\s*:\s*(.+)"));
/// facade_types.py:865: `re.sub(r'^pub(?:\s*\([^)]*\))?\s+', '', rest)`
static PUB: LazyLock<Regex> = LazyLock::new(|| compile(r"\Apub(?:\s*\([^)]*\))?\s+"));
/// facade_types.py:895: `\brepr\s*\(\s*([ui](?:8|16|32|64|size))\b`, its `\b`s checked by hand.
static REPR: LazyLock<Regex> = LazyLock::new(|| compile(r"repr\s*\(\s*([ui](?:8|16|32|64|size))"));
/// facade_types.py:930: `re.match(r'(\w+)\s*(.*)$', rest, re.S)`
static VARIANT: LazyLock<Regex> = LazyLock::new(|| compile(r"(?s)\A(\w+)\s*(.*)"));
/// facade_types.py:979
static MANUAL_STRING: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"serialize_str|collect_str|to_string\(\)\.serialize|as_str\(\)\.serialize|to_hex\(\)\.serialize",
    )
});
/// facade_types.py:980: `serialize_([ui]\d+|usize)`
static MANUAL_INT: LazyLock<Regex> = LazyLock::new(|| compile(r"serialize_([ui]\d+|usize)"));
/// facade_types.py:982: `serialize_f\d+`
static MANUAL_FLOAT: LazyLock<Regex> = LazyLock::new(|| compile(r"serialize_f\d+"));
/// facade_types.py:986: `self\.0\.serialize\(`
static MANUAL_SELF0: LazyLock<Regex> = LazyLock::new(|| compile(r"self\.0\.serialize\("));
/// facade_types.py:990: `\bself\.([A-Za-z_]\w*)\.serialize\(\s*serializer\s*\)`, its `\b` checked by hand.
static MANUAL_DELEGATE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"self\.([A-Za-z_]\w*)\.serialize\(\s*serializer\s*\)"));
/// facade_types.py:994: `re.match(r'(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?(\w+)\s*:\s*(.+)$', rest, re.S)`
static MANUAL_FIELD: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)\A(?:pub(?:\s*\([^)]*\))?\s+)?(?:r#)?(\w+)\s*:\s*(.+)"));
/// facade_types.py:1001: `(?:<\s*)?([A-Z]\w*)(?:\s+as\s+[\w:]*Deserialize[^>]*>)?::deserialize\(\s*deserializer`
static MANUAL_MIRROR: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?:<\s*)?([A-Z]\w*)(?:\s+as\s+[\w:]*Deserialize[^>]*>)?::deserialize\(\s*deserializer",
    )
});

/// The `(context, params)` a walk reads names in; Python passes both beside every type.
#[derive(Clone, Copy)]
pub(crate) struct Scope<'s> {
    pub(crate) context: &'s Context,
    pub(crate) params: &'s [String],
}

/// What a record holds besides its own fields: the `object()` arguments `hint` and `extra`.
struct Record {
    hint: Option<String>,
    extra: Vec<Field>,
}

impl Record {
    fn hinted(hint: String) -> Self {
        Self {
            hint: Some(hint),
            extra: Vec::new(),
        }
    }
}

impl Inventory {
    /// Port of facade_types.py:699-730 (`Inventory.ir`).
    pub(crate) fn ir(
        &mut self,
        ast: &Ast,
        context: &Context,
        params: &[String],
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let scope = Scope { context, params };
        self.walk(ast, scope, location)
    }

    /// One frame of `Inventory.ir`'s recursion (facade_types.py:699-730), around `walk_frame`: the frames are
    /// counted, so a walk as deep as Python's recursion limit is its `RecursionError`.
    fn walk(&mut self, ast: &Ast, scope: Scope<'_>, location: &str) -> Result<Ir, GenerateError> {
        self.enter()?;
        let value = self.walk_frame(ast, scope, location);
        self.leave();
        value
    }

    /// The body of `Inventory.ir` (facade_types.py:699-730).
    fn walk_frame(
        &mut self,
        ast: &Ast,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let (segments, args) = match ast {
            Ast::Ref(inner) => return self.walk(inner, scope, location),
            Ast::Tuple(items) if items.is_empty() => return Ok(NULL),
            Ast::Tuple(items) => {
                let items = items
                    .iter()
                    .map(|item| self.walk(item, scope, location))
                    .collect::<Result<_, _>>()?;
                return Ok(Ir::Tuple(items));
            }
            Ast::Array(item) => return Ok(Ir::Array(Box::new(self.walk(item, scope, location)?))),
            Ast::Raw(text) => return Ok(self.fallback(location, text, "unparseable type")),
            Ast::Path(segments, args) => (segments, args),
        };
        let mut name = segments.last().ok_or_else(index_error)?.clone();
        if segments.len() == 1 && scope.params.contains(&name) {
            return Ok(Ir::Param(name));
        }
        let mut external = holds(EXTERNAL, &segments[0]);
        let mut resolved = None;
        if !(external || (segments.len() == 1 && holds(PRELUDE, &name))) {
            let context = scope.context;
            match self.index.resolve(
                segments,
                &context.crate_name,
                &context.file,
                &context.module,
                0,
            )? {
                Some(Found::External(found)) => {
                    external = true;
                    name = found;
                }
                Some(Found::Item(item)) => resolved = Some(item),
                None => {}
            }
        }
        let Some(item) = resolved else {
            // A std or external type by its conventional wire spelling; a crate type the index cannot find is never
            // guessed into one.
            let conventional = external
                || holds(PRELUDE, &name)
                || holds(WRAPPERS, &name)
                || holds(SEQUENCES, &name)
                || holds(MAPS, &name);
            let found = if conventional {
                self.std(&name, args, scope, location)?
            } else {
                None
            };
            if let Some(found) = found {
                // `leaf is OPAQUE`: every opaque value is the one `OPAQUE` tuple.
                if found == Ir::Opaque {
                    self.opaques
                        .push((location.to_owned(), segments.join("::")));
                }
                return Ok(found);
            }
            let token = if external {
                None
            } else {
                self.index.macro_token(&name)
            };
            if let Some(token) = token {
                return Ok(token);
            }
            let reason = if external {
                "external type"
            } else {
                "unresolved type"
            };
            return Ok(self.fallback(location, &segments.join("::"), reason));
        };
        let key = self.declare(&item)?;
        let wanted = self.decl(&key)?.params.len();
        let mut arguments = args
            .iter()
            .map(|arg| self.walk(arg, scope, location))
            .collect::<Result<Vec<_>, _>>()?;
        arguments.truncate(wanted);
        while arguments.len() < wanted {
            arguments.push(Ir::Unknown("missing type argument".to_owned()));
        }
        Ok(Ir::Ref(key, arguments))
    }

    /// Port of facade_types.py:732-746 (`Inventory.std`): a std or external type the wire spells by convention, or
    /// `None`. Every argument is walked first.
    fn std(
        &mut self,
        name: &str,
        args: &[Ast],
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Option<Ir>, GenerateError> {
        let mut inner = args
            .iter()
            .map(|arg| self.walk(arg, scope, location))
            .collect::<Result<Vec<_>, _>>()?;
        if name == "Option" && !inner.is_empty() {
            return Ok(Some(Ir::Option(Box::new(inner.swap_remove(0)))));
        }
        if holds(WRAPPERS, name) && !inner.is_empty() {
            return Ok(Some(inner.swap_remove(0)));
        }
        if name == "Bytes" || name == "ByteBuf" {
            return Ok(Some(Ir::Array(Box::new(width("u8")))));
        }
        if holds(SEQUENCES, name) && !inner.is_empty() {
            return Ok(Some(Ir::Array(Box::new(inner.swap_remove(0)))));
        }
        if holds(MAPS, name) {
            if inner.len() > 1 {
                return Ok(Some(Ir::Map(Box::new(inner.swap_remove(1)))));
            }
            self.opaques.push((location.to_owned(), name.to_owned()));
            return Ok(Some(Ir::Map(Box::new(Ir::Opaque))));
        }
        if name == "Result" && inner.len() == 2 {
            let err = inner.swap_remove(1);
            let ok = inner.swap_remove(0);
            return Ok(Some(Ir::Union(vec![
                Ir::Object(vec![Field::new("Ok", ok, false)], Some("Ok".to_owned())),
                Ir::Object(vec![Field::new("Err", err, false)], Some("Err".to_owned())),
            ])));
        }
        Ok(leaf(name))
    }

    /// Port of facade_types.py:748-773 (`Inventory.codec`): a field under `with = codec`. A bounded codec reads
    /// the type itself; an id, hex, digest, base64 or decimal codec puts a string on the wire (a byte-id codec an
    /// array of numbers), under any `Option`, sequence or map around it; any other reads the mirror its module
    /// deserializes, else it is unread.
    fn codec(
        &mut self,
        ast: &Ast,
        codec: &str,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let leaf_name = codec.rsplit_once("::").map_or(codec, |(_, last)| last);
        if BOUNDED.is_match(codec) {
            return self.walk(ast, scope, location);
        }
        let wire = self
            .codec_place(codec, scope.context)?
            .and_then(|(target, path)| byte_id_codec(&target, &path));
        let stringy = wire.is_none() && STRINGY.is_match(&format!("{codec}::{leaf_name}"));
        if wire.is_none() && !stringy {
            if let Some((mirror, context)) = self.codec_mirror(codec, scope.context)? {
                let mirror_scope = Scope {
                    context: &context,
                    params: scope.params,
                };
                return self.walk(&parse_type(&mirror)?, mirror_scope, location);
            }
            return Ok(self.fallback(location, codec, "field codec"));
        }
        Ok(codec_walk(ast, &wire.unwrap_or(STRING)))
    }

    /// Port of facade_types.py:775-783 (`Inventory.codec_place`): the (crate, module path) a codec path names from
    /// its field's file; `None` for an external one.
    fn codec_place(
        &mut self,
        codec: &str,
        context: &Context,
    ) -> Result<Option<(String, Vec<String>)>, GenerateError> {
        let mut segments: Vec<String> = codec.split("::").map(str::to_owned).collect();
        let uses = self.index.uses(&context.crate_name, &context.file)?;
        if let Some(path) = uses.names.get(&segments[0]) {
            segments = [path.as_slice(), &segments[1..]].concat();
        }
        Ok(self
            .index
            .absolute(&segments, &context.crate_name, &context.module)?
            .filter(|(_, path)| !path.is_empty()))
    }

    /// Port of facade_types.py:785-813 (`Inventory.codec_mirror`): the wire mirror a codec module reads in its
    /// `deserialize` (`Option::<Row>::deserialize(deserializer)`), with the context its names resolve in; `None`
    /// when it reads none. The mirror an inline codec module declares takes the module's name.
    fn codec_mirror(
        &mut self,
        codec: &str,
        context: &Context,
    ) -> Result<Option<(String, Context)>, GenerateError> {
        let Some((target, path)) = self.codec_place(codec, context)? else {
            return Ok(None);
        };
        let own = self
            .index
            .modules
            .get(&(target.clone(), path.clone()))
            .cloned();
        let (text, place) = if let Some(own) = own {
            let text = self
                .index
                .files
                .get(&(target.clone(), own.clone()))
                .cloned()
                .unwrap_or_default();
            (
                text,
                Context {
                    crate_name: target,
                    file: own,
                    module: path,
                },
            )
        } else {
            let (last, parent_path) = path.split_last().ok_or_else(index_error)?;
            let Some(parent) = self
                .index
                .modules
                .get(&(target.clone(), parent_path.to_vec()))
                .cloned()
            else {
                return Ok(None);
            };
            let whole = self
                .index
                .files
                .get(&(target.clone(), parent.clone()))
                .cloned()
                .unwrap_or_default();
            let pattern = format!(
                r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+{}\s*\{{",
                regex::escape(last)
            );
            let inline = Regex::new(&crate::py::re::translate(&pattern))
                .map_err(|error| GenerateError::exception("re.error", error.to_string()))?;
            let Some(found) = inline.find(&whole) else {
                return Ok(None);
            };
            let open = found.end() - 1;
            let text = slice(&whole, open, close_of(&whole, open)).to_owned();
            let declared = declared_names(&text);
            let module_title: String = last.split('_').map(title).collect();
            for name in &declared {
                let Some(items) = self.index.items.get(name) else {
                    continue;
                };
                for item in items {
                    if item.crate_name == target && item.file == parent && !item.top {
                        let preferred = if declared.len() == 1 {
                            module_title.clone()
                        } else {
                            format!("{module_title}{name}")
                        };
                        self.preferred
                            .entry(Rc::clone(&item.key))
                            .or_insert(preferred);
                    }
                }
            }
            (
                text,
                Context {
                    crate_name: target,
                    file: parent,
                    module: parent_path.to_vec(),
                },
            )
        };
        let Some(fn_end) = deserialize_fn_end(&text) else {
            return Ok(None);
        };
        let open = find_from(&text, "{", fn_end).ok_or_else(substring_not_found)?;
        let body = slice(&text, fn_end, close_of(&text, open));
        let Some(read) = CODEC_READ.captures(body) else {
            return Ok(None);
        };
        if &read[1] == "Self" {
            return Ok(None);
        }
        Ok(Some((read[1].replace("::<", "<"), place)))
    }

    /// Port of facade_types.py:815-827 (`Inventory.field_ir`): a field's IR through its codec; the schema's own
    /// spelling (`schemars(with = ...)`) stands in only where the serde type could not be read.
    fn field_ir(
        &mut self,
        typ: &str,
        attrs: &str,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let schema = attr_args(attrs, "schemars")?;
        let serde = attr_args(attrs, "serde")?;
        let ast = parse_type(typ)?;
        let codec = or_value(serde.get("with"), serde.get("serialize_with"));
        let mark = self.fallbacks.len();
        let value = match codec {
            Some(Value::Str(codec)) => self.codec(&ast, codec, scope, location)?,
            _ => self.walk(&ast, scope, location)?,
        };
        if self.fallbacks.len() > mark
            && let Some(Value::Str(with)) = schema.get("with")
        {
            self.fallbacks.truncate(mark);
            return self.walk(&parse_type(with)?, scope, location);
        }
        Ok(value)
    }

    /// Port of facade_types.py:829-854 (`Inventory.fields`): named fields as `([(key, IR, optional)], [flattened
    /// IR])`.
    fn fields(
        &mut self,
        body: &str,
        case: Option<&Value>,
        container_default: bool,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<(Vec<Field>, Vec<Ir>), GenerateError> {
        let (mut out, mut flat) = (Vec::new(), Vec::new());
        for chunk in split_top(body, b',') {
            let (attrs, rest) = leading_attrs(chunk);
            let Some(found) = FIELD.captures(rest) else {
                continue;
            };
            let name = found[2].to_owned();
            let typ = strip(&found[3]).to_owned();
            let serde = attr_args(&attrs, "serde")?;
            if truthy(serde.get("skip"))
                || (truthy(serde.get("skip_serializing"))
                    && truthy(serde.get("skip_deserializing")))
            {
                continue;
            }
            let value = self.field_ir(&typ, &attrs, scope, &format!("{location}.{name}"))?;
            if truthy(serde.get("flatten")) {
                flat.push(match value {
                    Ir::Option(inner) => Ir::Partial(inner),
                    value => value,
                });
                continue;
            }
            let key = case_or(serialize_case(serde.get("rename")), || {
                Value::Str(rename(&name, case, false))
            });
            // serde reads a missing `Option` as `None` only without a field codec: under `with`/`deserialize_with`
            // and no `default` the key is required, `null` allowed (FIX 4287).
            let is_option = matches!(value, Ir::Option(_));
            let required_null = is_option
                && matches!(codec_of(&serde), Some(Value::Str(_)))
                && !serde.contains_key("default")
                && !container_default;
            let optional = (is_option && !required_null)
                || serde.contains_key("default")
                || container_default
                || serde.contains_key("skip_serializing_if")
                || is_true(serde.get("skip_serializing"))
                || is_true(serde.get("skip_deserializing"));
            if required_null {
                self.add_null_field(location, &key)?;
            }
            out.push(Field {
                key,
                value,
                optional,
            });
        }
        Ok((out, flat))
    }

    /// Port of facade_types.py:856-859 (`Inventory.object`).
    fn object(
        &mut self,
        body: &str,
        case: Option<&Value>,
        container_default: bool,
        scope: Scope<'_>,
        location: &str,
        record: Record,
    ) -> Result<Ir, GenerateError> {
        let (fields, mut flat) = self.fields(body, case, container_default, scope, location)?;
        let mut members = record.extra;
        members.extend(fields);
        let object = Ir::Object(members, record.hint);
        Ok(if flat.is_empty() {
            object
        } else {
            flat.push(object);
            Ir::And(flat)
        })
    }

    /// Port of facade_types.py:861-868 (`Inventory.tuple_fields`).
    fn tuple_fields(
        &mut self,
        body: &str,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Vec<Ir>, GenerateError> {
        let mut out = Vec::new();
        for (n, chunk) in split_top(body, b',').into_iter().enumerate() {
            let (attrs, rest) = leading_attrs(chunk);
            let rest = PUB.replace(rest, "");
            if truthy(attr_args(&attrs, "serde")?.get("skip")) {
                continue;
            }
            out.push(self.field_ir(&rest, &attrs, scope, &format!("{location}.{n}"))?);
        }
        Ok(out)
    }

    /// Port of facade_types.py:870-913 (`Inventory.item_ir`): what a type writes, its `into` type, else its own
    /// derive; a type that only reads takes the shape it reads `from`. A wire no caller can name is written under
    /// this type's own name (FIX 11203).
    pub(crate) fn item_ir(&mut self, item: &ItemRef, name: &str) -> Result<Ir, GenerateError> {
        self.enter()?;
        let value = self.item_ir_frame(item, name);
        self.leave();
        value
    }

    /// The body of `item_ir`, inside the frame it opens (two private conversions that name each other recurse here
    /// without end in Python, until its `RecursionError`).
    fn item_ir_frame(&mut self, item: &ItemRef, name: &str) -> Result<Ir, GenerateError> {
        let context = Context::of(item);
        let scope = Scope {
            context: &context,
            params: &item.generics,
        };
        let location = name;
        if item.kind == Kind::Type {
            return self.walk(&parse_type(&item.body)?, scope, location);
        }
        let serde = attr_args(&item.attrs, "serde")?;
        let derived = derives(&item.attrs);
        let conversions: &[&str] = if derived.contains("Serialize") {
            &["into"]
        } else {
            &["into", "try_from", "from"]
        };
        for key in conversions {
            let Some(Value::Str(target)) = serde.get(*key) else {
                continue;
            };
            let target = parse_type(target)?;
            let Some(wire) = self.private_wire(&target, item)? else {
                return self.walk(&target, scope, location);
            };
            let value = self.item_ir(&wire, name)?;
            if item.kind == Kind::Struct && !derived.contains("Debug") {
                self.redacted.insert(location.to_owned());
            }
            return Ok(value);
        }
        if !derived.contains("Serialize") && !derived.contains("Deserialize") {
            return self.manual(item, scope, location);
        }
        if derived.contains("Serialize_repr") || derived.contains("Deserialize_repr") {
            let repr = search_bounded(&REPR, &item.attrs, 0, true, true);
            return Ok(repr.map_or(INT, |found| width(&found[1])));
        }
        let case = serialize_case(serde.get("rename_all"));
        let default =
            is_true(serde.get("default")) || matches!(serde.get("default"), Some(Value::Str(_)));
        if is_true(serde.get("deny_unknown_fields")) {
            self.closed.insert(location.to_owned());
        }
        if item.kind == Kind::Struct && !derived.contains("Debug") {
            self.redacted.insert(location.to_owned());
        }
        if item.kind == Kind::Struct {
            if item.shape == Shape::Unit {
                return Ok(NULL);
            }
            if item.shape == Shape::Tuple {
                let mut values = self.tuple_fields(&item.body, scope, location)?;
                return Ok(if values.len() == 1 {
                    values.swap_remove(0)
                } else {
                    Ir::Tuple(values)
                });
            }
            if truthy(serde.get("transparent")) {
                let (mut fields, mut flat) =
                    self.fields(&item.body, None, false, scope, location)?;
                return Ok(if !fields.is_empty() {
                    fields.swap_remove(0).value
                } else if !flat.is_empty() {
                    flat.swap_remove(0)
                } else {
                    NULL
                });
            }
            let extra = match serde.get("tag") {
                Some(Value::Str(tag)) => {
                    let label = case_or(serialize_case(serde.get("rename")), || {
                        Value::Str(item.name.clone())
                    });
                    vec![Field {
                        key: Value::Str(tag.clone()),
                        value: Ir::Lit(label),
                        optional: false,
                    }]
                }
                _ => Vec::new(),
            };
            return self.object(
                &item.body,
                case.as_ref(),
                default,
                scope,
                location,
                Record { hint: None, extra },
            );
        }
        self.enum_ir(item, &serde, case.as_ref(), scope, location)
    }

    /// Port of facade_types.py:915-921 (`Inventory.private_wire`): the type a conversion of `item` names, when it is
    /// a non-generic one of its own file that is not `pub`; else `None`.
    fn private_wire(
        &mut self,
        ast: &Ast,
        item: &ItemRef,
    ) -> Result<Option<ItemRef>, GenerateError> {
        let Ast::Path(segments, args) = ast else {
            return Ok(None);
        };
        if !args.is_empty() {
            return Ok(None);
        }
        let found = self
            .index
            .resolve(segments, &item.crate_name, &item.file, &item.module, 0)?;
        let Some(Found::Item(found)) = found else {
            return Ok(None);
        };
        if Rc::ptr_eq(&found, item)
            || found.public
            || !found.generics.is_empty()
            || found.kind == Kind::Type
        {
            return Ok(None);
        }
        if (found.crate_name.as_str(), found.file.as_str())
            != (item.crate_name.as_str(), item.file.as_str())
        {
            return Ok(None);
        }
        Ok(Some(found))
    }

    /// Port of facade_types.py:923-971 (`Inventory.enum`): every variant as its member of the union, by the enum's
    /// tagging (untagged, adjacent, internal, external), with its metadata in `variants`.
    fn enum_ir(
        &mut self,
        item: &ItemRef,
        serde: &Dict,
        case: Option<&Value>,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let tag = match serde.get("tag") {
            Some(Value::Str(tag)) => Some(tag.clone()),
            _ => None,
        };
        let content = match serde.get("content") {
            Some(Value::Str(content)) => Some(content.clone()),
            _ => None,
        };
        let untagged = is_true(serde.get("untagged"));
        let field_case = serialize_case(serde.get("rename_all_fields"));
        let (mut members, mut variants) = (Vec::new(), Vec::new());
        for chunk in split_top(&item.body, b',') {
            let (attrs, rest) = leading_attrs(chunk);
            let Some(found) = VARIANT.captures(rest) else {
                continue;
            };
            let name = found[1].to_owned();
            let payload = strip(&found[2]).to_owned();
            let variant = attr_args(&attrs, "serde")?;
            if truthy(variant.get("skip"))
                || (truthy(variant.get("skip_serializing"))
                    && truthy(variant.get("skip_deserializing")))
            {
                continue;
            }
            let label = case_or(serialize_case(variant.get("rename")), || {
                Value::Str(rename(&name, case, true))
            });
            let inner_case = match serialize_case(variant.get("rename_all")) {
                Some(value) if value.truthy() => Some(value),
                _ => field_case.clone(),
            };
            let inner_case = inner_case.as_ref();
            let at = format!("{location}.{name}");
            let (shape, body, value) = if payload.starts_with('{') || payload.starts_with('(') {
                let body =
                    slice(&payload, 1, prev_char(&payload, close_of(&payload, 0))).to_owned();
                if payload.starts_with('{') {
                    (VariantShape::Struct, body, None)
                } else {
                    let mut values = self.tuple_fields(&body, scope, &at)?;
                    if values.len() == 1 {
                        (VariantShape::Newtype, body, Some(values.swap_remove(0)))
                    } else {
                        (VariantShape::Tuple, body, Some(Ir::Tuple(values)))
                    }
                }
            } else {
                (VariantShape::Unit, String::new(), None)
            };
            let variant_untagged = truthy(variant.get("untagged"));
            let member = if untagged || variant_untagged {
                match (shape, value) {
                    (VariantShape::Unit, _) => NULL,
                    (VariantShape::Struct, _) => self.object(
                        &body,
                        inner_case,
                        false,
                        scope,
                        &at,
                        Record::hinted(name.clone()),
                    )?,
                    (_, value) => value.unwrap_or(NULL),
                }
            } else if let (Some(tag), Some(content)) = (&tag, &content) {
                let mut fields = vec![Field::new(tag, Ir::Lit(label.clone()), false)];
                match (shape, value) {
                    (VariantShape::Struct, _) => {
                        let record = Record::hinted(format!("{name}Content"));
                        let body = self.object(&body, inner_case, false, scope, &at, record)?;
                        fields.push(Field::new(content, body, false));
                    }
                    (VariantShape::Unit, _) => {}
                    (_, value) => fields.push(Field::new(content, value.unwrap_or(NULL), false)),
                }
                Ir::Object(fields, Some(name.clone()))
            } else if let Some(tag) = &tag {
                let marker = Field::new(tag, Ir::Lit(label.clone()), false);
                match (shape, value) {
                    (VariantShape::Struct, _) => {
                        let record = Record {
                            hint: Some(name.clone()),
                            extra: vec![marker],
                        };
                        self.object(&body, inner_case, false, scope, &at, record)?
                    }
                    (VariantShape::Unit, _) => Ir::Object(vec![marker], Some(name.clone())),
                    (_, value) => Ir::And(vec![
                        value.unwrap_or(NULL),
                        Ir::Object(vec![marker], Some(name.clone())),
                    ]),
                }
            } else {
                match (shape, value) {
                    (VariantShape::Unit, _) => Ir::Lit(label.clone()),
                    (VariantShape::Struct, _) => {
                        let record = Record::hinted(format!("{name}Body"));
                        let body = self.object(&body, inner_case, false, scope, &at, record)?;
                        Ir::Object(
                            vec![Field {
                                key: label.clone(),
                                value: body,
                                optional: false,
                            }],
                            Some(name.clone()),
                        )
                    }
                    (_, value) => Ir::Object(
                        vec![Field {
                            key: label.clone(),
                            value: value.unwrap_or(NULL),
                            optional: false,
                        }],
                        Some(name.clone()),
                    ),
                }
            };
            members.push(member.clone());
            variants.push(VariantMeta {
                name,
                label,
                untagged: untagged || variant_untagged,
                other: is_true(variant.get("other")),
                shape,
                member,
            });
        }
        self.variants.insert(
            location.to_owned(),
            EnumMeta {
                tag,
                content,
                untagged,
                variants,
            },
        );
        Ok(match members.len() {
            0 => Ir::Never,
            1 => members.swap_remove(0),
            _ => Ir::Union(members),
        })
    }

    /// Port of facade_types.py:973-1008 (`Inventory.manual`): a type with a handwritten `Serialize`, as what its
    /// serializer writes when that is plain. Only the first `impl Serialize` found (of the item's crate, else any)
    /// is read.
    fn manual(
        &mut self,
        item: &ItemRef,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let all = self
            .index
            .impls
            .get(&item.name)
            .cloned()
            .unwrap_or_default();
        let own: Vec<_> = all
            .iter()
            .filter(|(crate_name, _, _)| *crate_name == item.crate_name)
            .cloned()
            .collect();
        let impls = if own.is_empty() { all } else { own };
        if let Some((crate_name, file, position)) = impls.into_iter().next() {
            let text = self
                .index
                .files
                .get(&(crate_name, file))
                .cloned()
                .unwrap_or_default();
            let open = find_from(&text, "{", position).ok_or_else(substring_not_found)?;
            let body = slice(&text, position, close_of(&text, open)).to_owned();
            if MANUAL_STRING.is_match(&body) {
                return Ok(STRING);
            }
            if let Some(written) = MANUAL_INT.captures(&body) {
                return Ok(width(&written[1]));
            }
            if MANUAL_FLOAT.is_match(&body) {
                return Ok(super::super::FLOAT);
            }
            if body.contains("serialize_bool") {
                return Ok(super::super::BOOL);
            }
            // `serialize_bytes`: serde_json writes the bytes as an array of numbers.
            if body.contains("serialize_bytes(") {
                return Ok(Ir::Array(Box::new(width("u8"))));
            }
            if item.shape == Shape::Tuple && MANUAL_SELF0.is_match(&body) {
                let mut values = self.tuple_fields(&item.body, scope, location)?;
                if !values.is_empty() {
                    return Ok(values.swap_remove(0));
                }
            }
            // A struct that writes one of its fields as itself writes that field.
            let delegate = search_bounded(&MANUAL_DELEGATE, &body, 0, true, false)
                .map(|found| found[1].to_owned());
            if let (Shape::Named, Some(delegate)) = (item.shape, delegate) {
                for chunk in split_top(&item.body, b',') {
                    let (attrs, rest) = leading_attrs(chunk);
                    let Some(found) = MANUAL_FIELD.captures(rest) else {
                        continue;
                    };
                    if found[1] == delegate {
                        let typ = strip(&found[2]).to_owned();
                        return self.field_ir(
                            &typ,
                            &attrs,
                            scope,
                            &format!("{location}.{}", &found[1]),
                        );
                    }
                }
            }
            // A handwritten pair that reads a wire mirror writes that mirror.
            for (crate2, file2, position2) in self
                .index
                .de_impls
                .get(&item.name)
                .cloned()
                .unwrap_or_default()
            {
                let text2 = self
                    .index
                    .files
                    .get(&(crate2.clone(), file2.clone()))
                    .cloned()
                    .unwrap_or_default();
                let open2 = find_from(&text2, "{", position2).ok_or_else(substring_not_found)?;
                let body2 = slice(&text2, position2, close_of(&text2, open2));
                if let Some(mirror) = MANUAL_MIRROR.captures(body2) {
                    let mirror = &mirror[1];
                    if !matches!(mirror, "Self" | "String") && mirror != item.name {
                        let context = Context {
                            crate_name: crate2,
                            file: file2,
                            module: item.module.clone(),
                        };
                        let mirror_scope = Scope {
                            context: &context,
                            params: scope.params,
                        };
                        return self.walk(&parse_type(mirror)?, mirror_scope, location);
                    }
                }
            }
            return Ok(self.fallback(location, &item.name, "handwritten Serialize"));
        }
        if item.shape == Shape::Tuple
            && item.kind == Kind::Struct
            && let Some(Value::Str(with)) = attr_args(&item.body, "schemars")?.get("with")
        {
            return self.walk(&parse_type(with)?, scope, location);
        }
        Ok(self.fallback(location, &item.name, "no serde derive"))
    }
}

/// The `walk` closure of facade_types.py:764-772: the codec's wire leaf under the `Option`, sequence (not of
/// `u8`) and map around the field's type.
fn codec_walk(node: &Ast, wire: &Ir) -> Ir {
    match node {
        Ast::Path(segments, args) => {
            let name = segments.last().map_or("", String::as_str);
            if name == "Option" && !args.is_empty() {
                return Ir::Option(Box::new(codec_walk(&args[0], wire)));
            }
            let of_bytes = matches!(&args.first(), Some(Ast::Path(inner, _)) if inner.last().is_some_and(|last| last == "u8"));
            if holds(SEQUENCES, name)
                && !matches!(name, "Bytes" | "ByteBuf")
                && !args.is_empty()
                && !of_bytes
            {
                return Ir::Array(Box::new(codec_walk(&args[0], wire)));
            }
            if holds(MAPS, name) && args.len() > 1 {
                return Ir::Map(Box::new(codec_walk(&args[1], wire)));
            }
            wire.clone()
        }
        Ast::Ref(inner) => codec_walk(inner, wire),
        _ => wire.clone(),
    }
}
