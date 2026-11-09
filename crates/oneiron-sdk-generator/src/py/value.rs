//! `Value`: a decoded JSON value with Python's meaning (DESIGN 3).
//!
//! The verb rows stay ordered JSON values, never typed structs (brief H1b): each row check is ported as written, with
//! Python's truthiness, `is True`, `==` and the errors Python raises when an operation meets the wrong type.

use indexmap::IndexMap;

use crate::error::GenerateError;
use crate::py::text::repr_str;

/// Python's `dict` of a JSON object: insertion order; a duplicate key keeps its first position and its last value.
pub(crate) type Dict = IndexMap<String, Value>;

/// A JSON value as Python's `json.loads` returns it.
#[derive(Debug, Clone)]
pub(crate) enum Value {
    /// `None` (`null`).
    None,
    /// `True`, `False`.
    Bool(bool),
    /// An `int`. Python's ints are unbounded; the port refuses a JSON integer outside `i64` (its one documented
    /// numeric divergence).
    Int(i64),
    /// A `float` (`1.0`, `1e3`, `NaN`, `Infinity`).
    Float(f64),
    /// A `str`.
    Str(String),
    /// A `list`.
    List(Vec<Value>),
    /// A `dict`.
    Dict(Dict),
}

/// A number as Python compares it: `bool` is an `int`, and `int == float` is exact.
#[derive(Clone, Copy)]
enum Number {
    Int(i64),
    Float(f64),
}

impl Number {
    fn py_eq(self, other: Self) -> bool {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Int(i), Self::Float(f)) | (Self::Float(f), Self::Int(i)) => {
                f.fract() == 0.0 && f.abs() < 1e38 && integral_to_i128(f) == i128::from(i)
            }
        }
    }
}

/// An integral float below 1e38 in magnitude as an `i128` (exact there).
#[allow(
    clippy::cast_possible_truncation,
    reason = "the caller checked the value is integral and in range"
)]
fn integral_to_i128(f: f64) -> i128 {
    f as i128
}

impl Value {
    /// `bool(value)`: `None`, `False`, `0`, `0.0`, `''`, `[]` and `{}` are false.
    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Dict(d) => !d.is_empty(),
        }
    }

    /// `value is True` (refuses `1`).
    pub(crate) fn is_true(&self) -> bool {
        matches!(self, Self::Bool(true))
    }

    /// `value is False` (refuses `0`).
    pub(crate) fn is_false(&self) -> bool {
        matches!(self, Self::Bool(false))
    }

    fn number(&self) -> Option<Number> {
        match self {
            Self::Bool(b) => Some(Number::Int(i64::from(*b))),
            Self::Int(i) => Some(Number::Int(*i)),
            Self::Float(f) => Some(Number::Float(*f)),
            _ => None,
        }
    }

    /// Python's `==`: `True == 1 == 1.0`, `NaN != NaN`, dicts equal whatever their order.
    ///
    /// Python's container comparison also takes an element as equal to itself by identity (`x is y`), so a list
    /// holding one NaN object equals itself. A clone here is that same object and two parsed NaNs are not; the port
    /// cannot tell them apart and compares by value (no comparison the generator makes depends on it).
    pub(crate) fn py_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::List(a), Self::List(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.py_eq(y))
            }
            (Self::Dict(a), Self::Dict(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| v.py_eq(w)))
            }
            _ => match (self.number(), other.number()) {
                (Some(a), Some(b)) => a.py_eq(b),
                _ => false,
            },
        }
    }

    /// `type(value).__name__`, as Python's `TypeError` texts name it.
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::None => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
        }
    }

    /// The text of a `str`.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// `value == '<text>'`: only a `str` equals a `str`.
    pub(crate) fn is_str(&self, text: &str) -> bool {
        self.as_str() == Some(text)
    }

    /// The entries of a `dict`.
    pub(crate) fn as_dict(&self) -> Option<&Dict> {
        match self {
            Self::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// `str(value)`, as an f-string interpolates it.
    pub(crate) fn str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            _ => self.repr(),
        }
    }

    /// `repr(value)`: `None`, `True`, `1`, `1.0`, `'text'`, `[1, 'a']`, `{'a': 1}`.
    pub(crate) fn repr(&self) -> String {
        match self {
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => float_repr(*f),
            Self::Str(s) => repr_str(s),
            Self::List(l) => format!(
                "[{}]",
                l.iter().map(Self::repr).collect::<Vec<_>>().join(", ")
            ),
            Self::Dict(d) => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{}: {}", repr_str(k), v.repr()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// `value[key]` with a `str` key: a dict's value, or Python's `KeyError`/`TypeError`.
    pub(crate) fn getitem(&self, key: &str) -> Result<&Value, GenerateError> {
        match self {
            Self::Dict(d) => d.get(key).ok_or_else(|| GenerateError::key(key)),
            Self::List(_) => Err(GenerateError::type_error(
                "list indices must be integers or slices, not str",
            )),
            Self::Str(_) => Err(GenerateError::type_error(
                "string indices must be integers, not 'str'",
            )),
            _ => Err(GenerateError::type_error(format!(
                "'{}' object is not subscriptable",
                self.type_name()
            ))),
        }
    }

    /// `value.get(key)`: a dict's value or `None` when absent; any other type has no `get`.
    pub(crate) fn dict_get(&self, key: &str) -> Result<Option<&Value>, GenerateError> {
        match self {
            Self::Dict(d) => Ok(d.get(key)),
            _ => Err(GenerateError::attribute(self.type_name(), "get")),
        }
    }

    /// `value.values()`.
    pub(crate) fn dict_values(&self) -> Result<Vec<&Value>, GenerateError> {
        match self {
            Self::Dict(d) => Ok(d.values().collect()),
            _ => Err(GenerateError::attribute(self.type_name(), "values")),
        }
    }

    /// `needle in value` with a `str` needle: a dict key, a list item, a substring.
    pub(crate) fn contains_str(&self, needle: &str) -> Result<bool, GenerateError> {
        match self {
            Self::Dict(d) => Ok(d.contains_key(needle)),
            Self::List(l) => Ok(l.iter().any(|item| item.is_str(needle))),
            Self::Str(s) => Ok(s.contains(needle)),
            _ => Err(GenerateError::type_error(format!(
                "argument of type '{}' is not a container or iterable",
                self.type_name()
            ))),
        }
    }

    /// `list(value)`: a dict's keys, a list's items, a string's characters.
    pub(crate) fn iterate(&self) -> Result<Vec<Value>, GenerateError> {
        match self {
            Self::Dict(d) => Ok(d.keys().map(|k| Self::Str(k.clone())).collect()),
            Self::List(l) => Ok(l.clone()),
            Self::Str(s) => Ok(s.chars().map(|c| Self::Str(c.to_string())).collect()),
            _ => Err(GenerateError::type_error(format!(
                "'{}' object is not iterable",
                self.type_name()
            ))),
        }
    }

    /// Refuses a value Python cannot hash: `cannot use 'list' as a set element (unhashable type: 'list')`.
    /// `role` is `a set element` or `a dict key`, as Python's text says.
    pub(crate) fn check_hashable(&self, role: &str) -> Result<(), GenerateError> {
        match self {
            Self::List(_) | Self::Dict(_) => {
                let name = self.type_name();
                Err(GenerateError::type_error(format!(
                    "cannot use '{name}' as {role} (unhashable type: '{name}')"
                )))
            }
            _ => Ok(()),
        }
    }

    /// `set(value)`, in first-seen order (Python iterates a set in hash order, so a caller sorts or tests membership).
    pub(crate) fn to_set(&self) -> Result<Vec<Value>, GenerateError> {
        let mut set: Vec<Value> = Vec::new();
        for item in self.iterate()? {
            set_add(&mut set, item)?;
        }
        Ok(set)
    }

    /// `len(value)`: a string's code points, a list's items, a dict's keys.
    pub(crate) fn py_len(&self) -> Result<usize, GenerateError> {
        match self {
            Self::Str(s) => Ok(s.chars().count()),
            Self::List(l) => Ok(l.len()),
            Self::Dict(d) => Ok(d.len()),
            _ => Err(GenerateError::type_error(format!(
                "object of type '{}' has no len()",
                self.type_name()
            ))),
        }
    }
}

/// `set.add(item)` on a set kept in first-seen order: equal items (`1`, `1.0`, `True`) keep the first.
pub(crate) fn set_add(set: &mut Vec<Value>, item: Value) -> Result<(), GenerateError> {
    item.check_hashable("a set element")?;
    if !set.iter().any(|seen| seen.py_eq(&item)) {
        set.push(item);
    }
    Ok(())
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.py_eq(other)
    }
}

/// `limbs * factor`, `limbs` a non-negative integer in base 10^9, least significant limb first.
fn big_mul_small(limbs: &mut Vec<u32>, factor: u32) {
    let mut carry = 0_u64;
    for limb in limbs.iter_mut() {
        let product = u64::from(*limb) * u64::from(factor) + carry;
        *limb = u32::try_from(product % 1_000_000_000).unwrap_or(0);
        carry = product / 1_000_000_000;
    }
    while carry > 0 {
        limbs.push(u32::try_from(carry % 1_000_000_000).unwrap_or(0));
        carry /= 1_000_000_000;
    }
}

/// The exact value of a finite, positive float as decimal digits `D` (no trailing zero) and a power of ten:
/// `f = D * 10^scale`. A float is `mantissa * 2^exponent`, and `2^-k = 5^k * 10^-k`.
fn exact_decimal(f: f64) -> (String, i32) {
    let bits = f.to_bits();
    let exponent_bits = i32::try_from((bits >> 52) & 0x7FF).unwrap_or(0);
    let fraction = bits & ((1 << 52) - 1);
    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, -1074)
    } else {
        (fraction | (1 << 52), exponent_bits - 1075)
    };
    let mut limbs = Vec::new();
    let mut rest = mantissa;
    while rest > 0 {
        limbs.push(u32::try_from(rest % 1_000_000_000).unwrap_or(0));
        rest /= 1_000_000_000;
    }
    let (factor, chunk, count) = if exponent >= 0 {
        (1_u32 << 30, 30, exponent)
    } else {
        (1_220_703_125_u32, 13, -exponent) // 5^13
    };
    for _ in 0..count / chunk {
        big_mul_small(&mut limbs, factor);
    }
    let last = if exponent >= 0 { 2_u32 } else { 5_u32 };
    for _ in 0..count % chunk {
        big_mul_small(&mut limbs, last);
    }
    let mut digits = limbs.last().map_or_else(String::new, u32::to_string);
    for limb in limbs.iter().rev().skip(1) {
        digits.push_str(&format!("{limb:09}"));
    }
    let scale = exponent.min(0);
    let trimmed = digits.trim_end_matches('0');
    let zeros = i32::try_from(digits.len() - trimmed.len()).unwrap_or(0);
    (trimmed.to_owned(), scale + zeros)
}

/// `digits + 1` of a decimal digit string (`"129"` is `"130"`, `"999"` is `"1000"`).
fn decimal_increment(digits: &str) -> String {
    let mut out: Vec<u8> = digits.bytes().collect();
    for at in (0..out.len()).rev() {
        if out[at] == b'9' {
            out[at] = b'0';
        } else {
            out[at] += 1;
            return String::from_utf8(out).unwrap_or_default();
        }
    }
    let mut carried = vec![b'1'];
    carried.extend(out);
    String::from_utf8(carried).unwrap_or_default()
}

/// The digits and decimal exponent of a finite, non-zero float's shortest round-trip form, as CPython's repr
/// (David Gay's dtoa, mode 0) chooses it: `1.5` is `("15", 0)`, `1e-7` is `("1", -7)` (the value is
/// `d1.d2d3... * 10^exponent`). Of the shortest digit strings that read back as the float, the one nearest its exact
/// value, a tie going to the even last digit.
fn shortest_digits(f: f64) -> (String, i32) {
    let f = f.abs();
    // Rust's `{:e}` writes a shortest round-trip string, so its length is the shortest length; but where two strings
    // of that length read back as the float it may take the other one (2**-25: Rust ...695313e-8, Python
    // ...695312e-8; Sol's G1a review, P1-1).
    let text = format!("{f:e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let rust_digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let rust_exponent: i32 = exponent.parse().unwrap_or(0);
    let shortest = rust_digits.len();
    let (exact, scale) = exact_decimal(f);
    let exact_exponent = i32::try_from(exact.len()).unwrap_or(0) - 1 + scale;
    if exact.len() <= shortest {
        return (exact, exact_exponent);
    }
    let reads_back = |digits: &str, exponent: i32| {
        let last = exponent - (i32::try_from(digits.len()).unwrap_or(0) - 1);
        format!("{digits}e{last}")
            .parse::<f64>()
            .is_ok_and(|back| back == f)
    };
    let (low, rest) = exact.split_at(shortest);
    let mut high = decimal_increment(low);
    let mut high_exponent = exact_exponent;
    if high.len() > shortest {
        high.truncate(shortest);
        high_exponent += 1;
    }
    let take_high = match (
        reads_back(low, exact_exponent),
        reads_back(&high, high_exponent),
    ) {
        (true, true) => match rest.as_bytes()[0].cmp(&b'5') {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            // `exact` has no trailing zero, so a `5` alone is the exact half-way point.
            std::cmp::Ordering::Equal => {
                rest.len() > 1 || (low.as_bytes()[shortest - 1] - b'0') % 2 == 1
            }
        },
        (false, true) => true,
        (true, false) => false,
        (false, false) => return (rust_digits, rust_exponent),
    };
    let (digits, exponent) = if take_high {
        (high, high_exponent)
    } else {
        (low.to_owned(), exact_exponent)
    };
    let trimmed = digits.trim_end_matches('0');
    (
        if trimmed.is_empty() {
            digits.clone()
        } else {
            trimmed.to_owned()
        },
        exponent,
    )
}

/// `repr(f)` of a finite float: `1.0`, `1e+16`, `1e-05`, `0.0001`, `-0.0` (an exponent below -4 or from 16 up
/// takes the scientific form, as `float_repr_style == 'short'` does).
fn finite_float_repr(f: f64) -> String {
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    let (digits, exponent) = shortest_digits(f);
    if (-4..16).contains(&exponent) {
        let point = exponent + 1;
        if point <= 0 {
            let zeros = "0".repeat(usize::try_from(-point).unwrap_or(0));
            format!("{sign}0.{zeros}{digits}")
        } else {
            let point = usize::try_from(point).unwrap_or(0);
            if digits.len() <= point {
                format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
            } else {
                format!("{sign}{}.{}", &digits[..point], &digits[point..])
            }
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let dot = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!(
            "{sign}{first}{dot}e{exp_sign}{:02}",
            exponent.unsigned_abs()
        )
    }
}

/// Python's `repr(float)` (and `str(float)`): `1.0`, `1e+16`, `1e-07`, `inf`, `-inf`, `nan`.
pub(crate) fn float_repr(f: f64) -> String {
    if f.is_nan() {
        "nan".to_owned()
    } else if f.is_infinite() {
        if f > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        }
    } else {
        finite_float_repr(f)
    }
}

/// `json.dumps(f)`: the repr, with `NaN`, `Infinity` and `-Infinity` for the special values.
pub(crate) fn float_json(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_owned()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".to_owned()
        } else {
            "-Infinity".to_owned()
        }
    } else {
        finite_float_repr(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Value {
        Value::Str(text.to_owned())
    }

    #[test]
    fn truthiness_and_identity() {
        for falsy in [
            Value::None,
            Value::Bool(false),
            Value::Int(0),
            Value::Float(0.0),
            s(""),
            Value::List(vec![]),
        ] {
            assert!(!falsy.truthy(), "{falsy:?}");
        }
        assert!(!Value::Dict(Dict::new()).truthy());
        for truthy in [
            Value::Bool(true),
            Value::Int(-1),
            Value::Float(f64::NAN),
            s("x"),
            Value::List(vec![Value::None]),
        ] {
            assert!(truthy.truthy(), "{truthy:?}");
        }
        assert!(Value::Bool(true).is_true());
        assert!(!Value::Int(1).is_true());
        assert!(!Value::Int(0).is_false());
    }

    // python3 -c "print(True == 1 == 1.0, 2**53 + 1 == float(2**53), float('nan') == float('nan'), {'a': 1, 'b': 2} == {'b': 2.0, 'a': True})"
    // prints: True False False True
    #[test]
    fn python_equality() {
        assert!(Value::Bool(true).py_eq(&Value::Int(1)));
        assert!(Value::Int(1).py_eq(&Value::Float(1.0)));
        assert!(Value::Int(0).py_eq(&Value::Float(-0.0)));
        assert!(!Value::Int((1 << 53) + 1).py_eq(&Value::Float(9_007_199_254_740_992.0)));
        assert!(!Value::Float(f64::NAN).py_eq(&Value::Float(f64::NAN)));
        assert!(!Value::Int(1).py_eq(&s("1")));
        assert!(!Value::None.py_eq(&Value::Bool(false)));
        let mut a = Dict::new();
        a.insert("a".into(), Value::Int(1));
        a.insert("b".into(), Value::Int(2));
        let mut b = Dict::new();
        b.insert("b".into(), Value::Float(2.0));
        b.insert("a".into(), Value::Bool(true));
        assert!(Value::Dict(a).py_eq(&Value::Dict(b)));
        assert!(
            Value::List(vec![Value::Int(1), s("a")])
                .py_eq(&Value::List(vec![Value::Float(1.0), s("a")]))
        );
    }

    // python3 -c "print(repr([1, 'a', None, 1.5, \"it's\"]), {'a': [True]}, str('x'), repr('x'), None, 1e16, float('inf'), repr(float('nan')), repr(-0.0))"
    // prints: [1, 'a', None, 1.5, "it's"] {'a': [True]} x 'x' None 1e+16 inf nan -0.0
    #[test]
    fn str_and_repr() {
        let list = Value::List(vec![
            Value::Int(1),
            s("a"),
            Value::None,
            Value::Float(1.5),
            s("it's"),
        ]);
        assert_eq!(list.repr(), "[1, 'a', None, 1.5, \"it's\"]");
        let mut d = Dict::new();
        d.insert("a".into(), Value::List(vec![Value::Bool(true)]));
        assert_eq!(Value::Dict(d).str(), "{'a': [True]}");
        assert_eq!(s("x").str(), "x");
        assert_eq!(s("x").repr(), "'x'");
        assert_eq!(Value::None.str(), "None");
        assert_eq!(Value::Float(1e16).str(), "1e+16");
        assert_eq!(Value::Float(f64::INFINITY).str(), "inf");
        assert_eq!(Value::Float(f64::NAN).repr(), "nan");
        assert_eq!(Value::Float(-0.0).repr(), "-0.0");
    }

    // The traceback's last line on nelly (Python 3.14.7) of, for example, `python3 -c "[1]['name']"`,
    // `python3 -c "'x' in 1"`, `python3 -c "set([[1]])"` and `python3 -c "[1].get('x')"`.
    #[test]
    fn python_errors_by_type() {
        let int = Value::Int(1);
        let list = Value::List(vec![Value::Int(1)]);
        let text = s("abc");
        let msg = |r: Result<(), GenerateError>| r.expect_err("an error").to_string();
        assert_eq!(
            msg(list.getitem("name").map(drop)),
            "TypeError: list indices must be integers or slices, not str"
        );
        assert_eq!(
            msg(text.getitem("name").map(drop)),
            "TypeError: string indices must be integers, not 'str'"
        );
        assert_eq!(
            msg(int.getitem("name").map(drop)),
            "TypeError: 'int' object is not subscriptable"
        );
        assert_eq!(
            msg(Value::None.getitem("name").map(drop)),
            "TypeError: 'NoneType' object is not subscriptable"
        );
        assert_eq!(
            msg(Value::Bool(true).getitem("name").map(drop)),
            "TypeError: 'bool' object is not subscriptable"
        );
        assert_eq!(
            msg(Value::Dict(Dict::new()).getitem("name").map(drop)),
            "KeyError: 'name'"
        );
        assert_eq!(
            msg(int.contains_str("x").map(drop)),
            "TypeError: argument of type 'int' is not a container or iterable"
        );
        assert_eq!(
            msg(Value::None.contains_str("x").map(drop)),
            "TypeError: argument of type 'NoneType' is not a container or iterable"
        );
        assert_eq!(
            msg(Value::Float(1.5).iterate().map(drop)),
            "TypeError: 'float' object is not iterable"
        );
        assert_eq!(
            msg(Value::Bool(true).to_set().map(drop)),
            "TypeError: 'bool' object is not iterable"
        );
        assert_eq!(
            msg(Value::List(vec![list.clone()]).to_set().map(drop)),
            "TypeError: cannot use 'list' as a set element (unhashable type: 'list')"
        );
        assert_eq!(
            msg(Value::List(vec![Value::Dict(Dict::new())])
                .to_set()
                .map(drop)),
            "TypeError: cannot use 'dict' as a set element (unhashable type: 'dict')"
        );
        assert_eq!(
            msg(list.dict_get("x").map(drop)),
            "AttributeError: 'list' object has no attribute 'get'"
        );
        assert_eq!(
            msg(text.dict_values().map(drop)),
            "AttributeError: 'str' object has no attribute 'values'"
        );
        assert_eq!(
            msg(Value::None.py_len().map(drop)),
            "TypeError: object of type 'NoneType' has no len()"
        );
    }

    // python3 -c "print('.' in 'a.b', 'rows' in ['rows'], 'rows' in ['rowsx'], len({1, 1.0, True, '1', float('nan')}), len(set('aé')), len('aé'))"
    // prints: True True False 3 2 2
    #[test]
    fn python_container_operations() {
        assert!(s("a.b").contains_str(".").expect("str"));
        assert!(
            Value::List(vec![s("rows")])
                .contains_str("rows")
                .expect("list")
        );
        assert!(
            !Value::List(vec![s("rowsx")])
                .contains_str("rows")
                .expect("list")
        );
        let set = Value::List(vec![
            Value::Int(1),
            Value::Float(1.0),
            Value::Bool(true),
            s("1"),
            Value::Float(f64::NAN),
        ])
        .to_set()
        .expect("hashable");
        assert_eq!(set.len(), 3);
        assert!(matches!(set[0], Value::Int(1)));
        assert_eq!(s("aé").to_set().expect("str").len(), 2);
        assert_eq!(s("aé").py_len().expect("str"), 2);
    }

    // Each expected value: python3 -c "import struct; print(repr(struct.unpack('<d', struct.pack('<Q', BITS))[0]))"
    // on nelly (Python 3.14.7), BITS being the row's first value (random finite floats, then fixed cases).
    #[test]
    fn float_repr_matches_python() {
        let cases: &[(u64, &str)] = &[
            (0x0c2ff3302f051967, "5.5780685715890197e-250"),
            (0x4a4724bf7d64313d, "6.764866338364554e+49"),
            (0x23563bf79e7d4c89, "1.867086468513826e-138"),
            (0x5f114d466c957441, "8.84933318704696e+149"),
            (0x0216f3b42eaed5bf, "1.370895156118858e-298"),
            (0x773b202edecf6301, "2.1866404701661542e+266"),
            (0x186a22a9e07b2f67, "4.582705934104935e-191"),
            (0xf123b3b9fe66f172, "-1.0023010179898752e+237"),
            (0x7e3cf6de3481567b, "1.2123252671822697e+300"),
            (0x5f6d31d436bc30c1, "4.7782737350221646e+151"),
            (0xd6861eb9f9bd1895, "-6.493727657350955e+108"),
            (0x51877e4a294d2956, "5.704967526787427e+84"),
            (0xf27c0181a6cc4dc0, "-2.9878982809043733e+243"),
            (0xee39ee03d78a925f, "-9.372923519857944e+222"),
            (0xcd8484634d70b56c, "-2.7008838209119595e+65"),
            (0x29546a95eb6099c5, "1.3583124806119083e-109"),
            (0x6c7ab3655edd8d84, "3.5955111789289255e+214"),
            (0x37b0bf026665a016, "1.922361489174045e-40"),
            (0x9e1afd4b9435f19c, "-1.1716992512397343e-163"),
            (0xdc538e036b509570, "-5.685256815091975e+136"),
            (0xc67ad722b358491f, "-3.4024215246280187e+31"),
            (0x1639dffff89fa6f2, "1.320453964684392e-201"),
            (0x2f4efbba3009e56b, "8.165804607520428e-81"),
            (0x40d5843cb27fc656, "22032.948394721687"),
            (0x9172317228b05ded, "-1.2287714157834947e-224"),
            (0x744313d2d875c424, "1.0927137130994592e+252"),
            (0x4c01f1a3220e6477, "1.407945716842748e+58"),
            (0x5b4a77005104214f, "5.870262689145382e+131"),
            (0x7a605b4ca21f95f9, "2.969067064539557e+281"),
            (0x2da472d6c42aa793, "8.030722995907791e-89"),
            (0x23d849d776074a0c, "5.221336228213846e-136"),
            (0xdd74b8308d633277, "-1.5791269658656463e+142"),
            (0x5519bd4a30220c99, "9.007768052616988e+101"),
            (0xb21ee1acf4dfe8bc, "-2.8636504495586237e-67"),
            (0x0eb0fe9214734cf0, "6.524536904262904e-238"),
            (0xfe4ce6d425104026, "-2.4194057083173788e+300"),
            (0xed02d3809cca23fd, "-1.2979833631725913e+217"),
            (0x3cf5a743afd06a2f, "4.808015445380092e-15"),
            (0x63d593ce0f290b88, "8.33865288228098e+172"),
            (0x3ebead9541f0abdd, "1.8285547935907773e-06"),
            (0x4da76948d22c6d9b, "1.2327471109132115e+66"),
            (0x8c5fe4dbdf64615d, "-4.4546369624763854e-249"),
            (0xe462b511f4449831, "-3.701508246241328e+175"),
            (0x26c1f61b9d9c1f28, "5.434141655041293e-122"),
            (0x83489acaa7dfa4e7, "-7.704979784671961e-293"),
            (0x9fe7c00daf088dfe, "-5.535535926426257e-155"),
            (0x7313d1c4b11bcca1, "2.165245467943009e+246"),
            (0x6490fafbbb88d095, "2.68785283069896e+176"),
            (0xad149c63c201148e, "-1.5809503230980738e-91"),
            (0xcaaa0d957ddc15de, "-4.873803932874969e+51"),
            (0x06aaf07de89aaa0e, "1.5197153644568326e-276"),
            (0x80eb56b37314ad4f, "-3.1145253164819867e-304"),
            (0x1a93ec882f2a08ad, "1.2003782535445763e-180"),
            (0x002f698c3f812409, "8.736834907041892e-308"),
            (0xdd562793d6b45d16, "-4.221257882750206e+141"),
            (0x3298025a0b97842d, "5.6995214189970755e-65"),
            (0x120037bcf5cfc715, "5.608196102287852e-222"),
            (0x0cbb14841df02f19, "2.420663898854312e-247"),
            (0x2138f37567274df6, "1.2195799727200376e-148"),
            (0x6eac675c1162f5b4, "1.314202951871281e+225"),
            (0x0000000000000000, "0.0"),
            (0x031f8997a63a8424, "1.2345e-293"),
            (0x0acda85eaa5c8cef, "1.2344999999999999e-256"),
            (0x127be3d48a4b139a, "1.2345e-219"),
            (0x1a2a3a439b21178d, "1.2345e-182"),
            (0x21d8aa10483ce3f5, "1.2344999999999998e-145"),
            (0x298731b78532124f, "1.2345e-108"),
            (0x3135cfcd57755e9f, "1.2344999999999998e-71"),
            (0x38e482fb7658467e, "1.2344999999999998e-34"),
            (0x40934a0000000000, "1234.5"),
            (0x484223ac4217a08b, "1.2345e+40"),
            (0x4ff10ee3951060c1, "1.2345e+77"),
            (0x57a00a9a48d4dc9b, "1.2345e+114"),
            (0x5f4e2ba943ca1e48, "1.2344999999999999e+151"),
            (0x66fc5f4bcbc14fa7, "1.2345e+188"),
            (0x6eaaae5eed28882e, "1.2344999999999998e+225"),
            (0x7659173ff55840ed, "1.2345e+262"),
            (0x7e07986526780e92, "1.2345e+299"),
            (0x3fb999999999999a, "0.1"),
            (0x3fc999999999999a, "0.2"),
            (0x3fd3333333333333, "0.3"),
            (0x3fd5555555555555, "0.3333333333333333"),
            (0x3fe5555555555555, "0.6666666666666666"),
            (0x4059000000000000, "100.0"),
            (0x430c6bf526340000, "1000000000000000.0"),
            (0x4341c37937e08000, "1e+16"),
            (0x4340000000000000, "9007199254740992.0"),
            (0x40fe240c9fbe76c9, "123456.789"),
            (0x3f1a36e2eb1c432d, "0.0001"),
            (0x3f1a36371ea531a8, "9.999e-05"),
            (0x0000000000000001, "5e-324"),
            (0x0010000000000000, "2.2250738585072014e-308"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
        ];
        for (bits, expected) in cases {
            assert_eq!(float_repr(f64::from_bits(*bits)), *expected, "{bits:#x}");
        }
        // Ties between two shortest strings (Sol's G1a review, P1-1): python3 -c "print(repr(2**-25), repr(2.0**-1074), repr(2.0**-1022), repr(2.0**60), repr(2.0**-100))"
        assert_eq!(float_repr(2.0_f64.powi(-25)), "2.9802322387695312e-08");
        assert_eq!(float_repr(f64::from_bits(1)), "5e-324");
        assert_eq!(float_repr(f64::MIN_POSITIVE), "2.2250738585072014e-308");
        assert_eq!(
            float_repr(1_152_921_504_606_846_976.0),
            "1.152921504606847e+18"
        );
        assert_eq!(
            float_repr(7.888_609_052_210_118e-31),
            "7.888609052210118e-31"
        );
        assert_eq!(float_json(f64::NAN), "NaN");
        assert_eq!(float_json(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(float_json(1e-7), "1e-07");
        assert_eq!(float_json(1000.0), "1000.0");
    }
}
