//! SVG number, path-data and transform grammars, strict: a string that is not
//! in the grammar is refused whole, where a browser would draw up to the
//! error.

use super::Refused;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct P {
    pub(super) x: f64,
    pub(super) y: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Seg {
    Line(P),
    Cubic(P, P, P),
    Quad(P, P),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Subpath {
    pub(super) start: P,
    pub(super) segs: Vec<Seg>,
    pub(super) closed: bool,
}

/// `x' = a x + c y + e`, `y' = b x + d y + f`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Affine {
    pub(super) a: f64,
    pub(super) b: f64,
    pub(super) c: f64,
    pub(super) d: f64,
    pub(super) e: f64,
    pub(super) f: f64,
}

impl Affine {
    pub(super) const IDENTITY: Self = Self::scale(1.0, 1.0);

    const fn scale(sx: f64, sy: f64) -> Self {
        Self {
            a: sx,
            b: 0.0,
            c: 0.0,
            d: sy,
            e: 0.0,
            f: 0.0,
        }
    }

    const fn translate(tx: f64, ty: f64) -> Self {
        Self {
            e: tx,
            f: ty,
            ..Self::IDENTITY
        }
    }

    fn rotate(degrees: f64) -> Self {
        let (sin, cos) = degrees.to_radians().sin_cos();
        Self {
            a: cos,
            b: sin,
            c: -sin,
            d: cos,
            e: 0.0,
            f: 0.0,
        }
    }

    /// `self` after `inner`: `inner` applies to points first.
    pub(super) fn then(self, inner: Self) -> Self {
        Self {
            a: self.a * inner.a + self.c * inner.b,
            b: self.b * inner.a + self.d * inner.b,
            c: self.a * inner.c + self.c * inner.d,
            d: self.b * inner.c + self.d * inner.d,
            e: self.a * inner.e + self.c * inner.f + self.e,
            f: self.b * inner.e + self.d * inner.f + self.f,
        }
    }

    pub(super) fn apply(self, p: P) -> P {
        P {
            x: self.a * p.x + self.c * p.y + self.e,
            y: self.b * p.x + self.d * p.y + self.f,
        }
    }
}

struct Lexer<'a> {
    s: &'a [u8],
    at: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            at: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at == self.s.len()
    }

    fn wsp(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.at += 1;
        }
    }

    /// `wsp* (',' wsp*)?`
    fn comma_wsp(&mut self) {
        self.wsp();
        if self.peek() == Some(b',') {
            self.at += 1;
            self.wsp();
        }
    }

    fn at_number(&self) -> bool {
        matches!(self.peek(), Some(b'0'..=b'9' | b'+' | b'-' | b'.'))
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.at += 1;
        }
        self.at - start
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.at;
        if matches!(self.peek(), Some(b'+' | b'-')) {
            self.at += 1;
        }
        let mut digits = self.digits();
        if self.peek() == Some(b'.') {
            self.at += 1;
            digits += self.digits();
        }
        if digits == 0 {
            return None;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mantissa = self.at;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                self.at = mantissa;
            }
        }
        let value: f64 = std::str::from_utf8(self.s.get(start..self.at)?)
            .ok()?
            .parse()
            .ok()?;
        value.is_finite().then_some(value)
    }

    /// The next argument: a number after an optional separator.
    fn argument(&mut self) -> Option<f64> {
        self.comma_wsp();
        self.number()
    }

    fn pair(&mut self) -> Option<P> {
        Some(P {
            x: self.argument()?,
            y: self.argument()?,
        })
    }

    /// Whether another argument set follows, consuming its separator.
    fn more(&mut self) -> bool {
        let save = self.at;
        self.comma_wsp();
        if self.at_number() {
            return true;
        }
        self.at = save;
        false
    }
}

/// A whole-string number.
pub(super) fn number(s: &str) -> Option<f64> {
    let mut lexer = Lexer::new(s.trim());
    let value = lexer.number()?;
    lexer.done().then_some(value)
}

/// A comma-wsp separated number list.
pub(super) fn numbers(s: &str) -> Option<Vec<f64>> {
    let mut lexer = Lexer::new(s.trim());
    let mut values = Vec::new();
    while !lexer.done() {
        if !values.is_empty() {
            lexer.comma_wsp();
        }
        values.push(lexer.number()?);
    }
    Some(values)
}

/// Path data in M L H V C Q Z, absolute only (`z` is the same command).
pub(super) fn path_data(d: &str) -> Result<Vec<Subpath>, Refused> {
    let bad = || Refused::Value("d".to_owned());
    let mut lexer = Lexer::new(d);
    let mut subpaths: Vec<Subpath> = Vec::new();
    let mut current = P { x: 0.0, y: 0.0 };
    lexer.wsp();
    if lexer.peek() != Some(b'M') {
        return Err(match lexer.peek() {
            Some(b) if b.is_ascii_alphabetic() => Refused::PathCommand(char::from(b)),
            _ => bad(),
        });
    }
    while !lexer.done() {
        let command = char::from(lexer.peek().ok_or_else(bad)?);
        lexer.at += 1;
        if command == 'M' {
            current = lexer.pair().ok_or_else(bad)?;
            subpaths.push(Subpath {
                start: current,
                segs: Vec::new(),
                closed: false,
            });
            while lexer.more() {
                current = lexer.pair().ok_or_else(bad)?;
                open(&mut subpaths).segs.push(Seg::Line(current));
            }
        } else if matches!(command, 'Z' | 'z') {
            let sub = open(&mut subpaths);
            sub.closed = true;
            current = sub.start;
        } else {
            if subpaths.last().is_some_and(|sub| sub.closed) {
                subpaths.push(Subpath {
                    start: current,
                    segs: Vec::new(),
                    closed: false,
                });
            }
            loop {
                let seg = match command {
                    'L' => Seg::Line(lexer.pair().ok_or_else(bad)?),
                    'H' => Seg::Line(P {
                        x: lexer.argument().ok_or_else(bad)?,
                        y: current.y,
                    }),
                    'V' => Seg::Line(P {
                        x: current.x,
                        y: lexer.argument().ok_or_else(bad)?,
                    }),
                    'C' => Seg::Cubic(
                        lexer.pair().ok_or_else(bad)?,
                        lexer.pair().ok_or_else(bad)?,
                        lexer.pair().ok_or_else(bad)?,
                    ),
                    'Q' => Seg::Quad(lexer.pair().ok_or_else(bad)?, lexer.pair().ok_or_else(bad)?),
                    other if other.is_ascii_alphabetic() => {
                        return Err(Refused::PathCommand(other));
                    }
                    _ => return Err(bad()),
                };
                current = match seg {
                    Seg::Line(end) | Seg::Cubic(_, _, end) | Seg::Quad(_, end) => end,
                };
                open(&mut subpaths).segs.push(seg);
                if !lexer.more() {
                    break;
                }
            }
        }
        lexer.wsp();
    }
    if subpaths.iter().any(|sub| sub.segs.is_empty()) {
        return Err(bad());
    }
    Ok(subpaths)
}

/// The subpath being drawn; path data always starts with M, so one exists.
fn open(subpaths: &mut Vec<Subpath>) -> &mut Subpath {
    if subpaths.is_empty() {
        subpaths.push(Subpath {
            start: P { x: 0.0, y: 0.0 },
            segs: Vec::new(),
            closed: false,
        });
    }
    let last = subpaths.len() - 1;
    &mut subpaths[last]
}

/// A transform list of translate, scale and rotate.
pub(super) fn transform(s: &str) -> Result<Affine, Refused> {
    let bad = || Refused::Value("transform".to_owned());
    let mut rest = s.trim();
    let mut total = Affine::IDENTITY;
    while !rest.is_empty() {
        let open = rest.find('(').ok_or_else(bad)?;
        let close = rest.find(')').ok_or_else(bad)?;
        let name = rest[..open].trim();
        let args = numbers(rest.get(open + 1..close).ok_or_else(bad)?).ok_or_else(bad)?;
        let step = match (name, args.as_slice()) {
            ("translate", &[tx]) => Affine::translate(tx, 0.0),
            ("translate", &[tx, ty]) => Affine::translate(tx, ty),
            ("scale", &[s]) if s > 0.0 => Affine::scale(s, s),
            ("scale", &[sx, sy]) if sx > 0.0 && sy > 0.0 => Affine::scale(sx, sy),
            ("scale", _) | ("matrix" | "skewX" | "skewY", _) => return Err(Refused::Transform),
            ("rotate", &[angle]) => Affine::rotate(angle),
            ("rotate", &[angle, cx, cy]) => Affine::translate(cx, cy)
                .then(Affine::rotate(angle))
                .then(Affine::translate(-cx, -cy)),
            _ => return Err(bad()),
        };
        total = total.then(step);
        rest = rest[close + 1..].trim_start();
        if let Some(after) = rest.strip_prefix(',') {
            rest = after.trim_start();
        }
    }
    Ok(total)
}
