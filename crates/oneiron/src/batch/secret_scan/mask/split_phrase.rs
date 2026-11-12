//! A recovery phrase split over a file's parts (LABEL-04; ARCH-0038
//! #promise-label-04): one word per MessagePack item or JSON byte array, at
//! any depth, or between the bytes that frame those items. The door reads it
//! whole, in the leaf's decoded parts joined or in its lossy text, where no
//! run of valid text holds it, so no text span places it. Each word is found
//! at its bytes in the leaf: one custody record holds the phrase, and the
//! file's mark covers each word (owner ruling G04 binary = C2). In a body
//! that is no file, [`ArrayText`] and [`Spread::smallest_part`] name the
//! smallest value that reads as the phrase, which takes the handle whole; in
//! a value that reads as more than that phrase, the items that read as it
//! take the handle and the rest stay as written (REVIEW-7060 P1).

use std::ops::Range;

use rmpv::Value;
use zeroize::Zeroizing;

use super::super::{byte_values, shapes};
use super::wipe::PlanTree;
use crate::file_secret_marks::FILLER;

/// One recovery phrase a reading found split over a leaf.
pub(super) struct SplitPhrase {
    /// The phrase's words, one space between them: the value custody holds.
    pub(super) value: Zeroizing<Vec<u8>>,
    /// Each word's span in the leaf, in order.
    pub(super) words: Vec<Range<usize>>,
}

/// Each recovery phrase the door's readings of `leaf` find split over its
/// parts: its decoded parts as the field walk reads them (each array first
/// as one text: its byte values, or its text items one per line), then its
/// lossy text, as the text rules read a body that is no valid UTF-8.
pub(super) fn split_phrases(leaf: &[u8]) -> Vec<SplitPhrase> {
    let mut phrases = Vec::new();
    if let Some((tree, node)) = decoded(leaf) {
        read_part(&tree.0, &node, &mut phrases);
        // The whole read: every text the leaf carries, one per line.
        read_text(&mut phrases, |text| {
            text.push_leaves(&tree.0, &node);
            true
        });
    }
    // Valid UTF-8 is one run of text to the text rules, which placed what
    // it holds.
    if std::str::from_utf8(leaf).is_err() {
        read_text(&mut phrases, |text| {
            text.push_bytes(leaf, 0);
            true
        });
    }
    phrases
}

/// An array read as one text, as the field walk reads an array before its
/// items (its byte values, or its text items one per line, two at least),
/// with the bytes each piece of that text reads. The text is wiped when it
/// drops.
pub(super) struct ArrayText {
    text: Zeroizing<String>,
    pieces: Vec<ArrayPiece>,
    /// Whether the text reads every item: no number, map or nil sits beside
    /// the text items.
    every_item: bool,
}

/// One piece of an array's text: the item it reads (`None`: the array's own
/// byte values, all of them), whether that item is a string, its bytes, and
/// where its text sits.
struct ArrayPiece {
    item: Option<usize>,
    string: bool,
    bytes: Zeroizing<Vec<u8>>,
    text: Range<usize>,
}

/// How an array is written once each phrase it places takes its handle.
pub(super) struct Placement {
    /// For each piece of the text a phrase touches, its bytes as written
    /// next: the runs it keeps, and where each handle goes. An empty one is
    /// an item the phrases cover whole, which goes.
    pieces: Vec<Option<Vec<Cut>>>,
    /// The array reads as one phrase and nothing else: its handle stands for
    /// the array whole, as a credential field's value.
    whole: bool,
}

/// One run of a piece's bytes as written next.
enum Cut {
    /// Bytes kept as written.
    Keep(Range<usize>),
    /// The handle of the phrase at this index.
    Handle(usize),
}

impl ArrayText {
    /// `items` read as one text, as the field walk reads an array before its
    /// items: `None` when it reads none (no byte values, fewer than two text
    /// items).
    pub(super) fn of(items: &[Value]) -> Option<Self> {
        if let Some(bytes) = byte_values(items.iter().map(Value::as_u64)) {
            let bytes = Zeroizing::new(bytes);
            let text = lossy(&bytes);
            let piece = ArrayPiece {
                item: None,
                string: false,
                bytes,
                text: 0..text.len(),
            };
            return Some(Self {
                text,
                pieces: vec![piece],
                every_item: true,
            });
        }
        let mut pieces = Vec::new();
        let mut texts = Vec::new();
        for (at, item) in items.iter().enumerate() {
            if let Some(bytes) = item_bytes(item) {
                texts.push(lossy(&bytes));
                pieces.push(ArrayPiece {
                    item: Some(at),
                    string: matches!(item, Value::String(_)),
                    bytes,
                    text: 0..0,
                });
            }
        }
        if pieces.len() < 2 {
            return None;
        }
        let mut text = Zeroizing::new(String::with_capacity(
            texts.iter().map(|text| text.len() + 1).sum(),
        ));
        for (at, (piece, piece_text)) in pieces.iter_mut().zip(&texts).enumerate() {
            if at > 0 {
                text.push('\n');
            }
            let start = text.len();
            text.push_str(piece_text);
            piece.text = start..text.len();
        }
        Some(Self {
            text,
            every_item: pieces.len() == items.len(),
            pieces,
        })
    }

    /// Each recovery phrase the text holds, in order: its words, one space
    /// between them, and its span in the text.
    pub(super) fn phrases(&self) -> Vec<(Zeroizing<Vec<u8>>, Range<usize>)> {
        phrases_in(&self.text)
    }

    /// How the array is written once the phrase at each of `spans` takes a
    /// handle, the rest kept as written: `None` when no span is given, two
    /// overlap, or a run kept would not be the item's bytes as written.
    pub(super) fn placement(&self, spans: &[Range<usize>]) -> Option<Placement> {
        if spans.is_empty() || spans.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return None;
        }
        let mut pieces = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let mut cuts = Vec::new();
            let mut at = piece.text.start;
            let mut touched = false;
            for (place, span) in spans.iter().enumerate() {
                if span.end <= piece.text.start || span.start >= piece.text.end {
                    continue;
                }
                touched = true;
                if span.start > at {
                    cuts.push(Cut::Keep(piece.kept(at..span.start)?));
                }
                if span.start >= piece.text.start {
                    cuts.push(Cut::Handle(place));
                }
                at = at.max(span.end.min(piece.text.end));
            }
            if touched && at < piece.text.end {
                cuts.push(Cut::Keep(piece.kept(at..piece.text.end)?));
            }
            pieces.push(touched.then_some(cuts));
        }
        let whole = spans.len() == 1
            && self.every_item
            && pieces.iter().all(|cuts| {
                cuts.as_ref()
                    .is_some_and(|cuts| cuts.iter().all(|cut| matches!(cut, Cut::Handle(_))))
            });
        Some(Placement { pieces, whole })
    }

    /// The array `items` as `placement` writes it, the phrase at each span
    /// replaced by its handle in `handles`.
    pub(super) fn written(
        &self,
        items: &[Value],
        placement: &Placement,
        handles: &[String],
    ) -> Value {
        if let (true, Some(handle)) = (placement.whole, handles.first()) {
            return Value::from(handle.as_str());
        }
        let mut rewritten: Vec<Option<Option<Value>>> = vec![None; items.len()];
        for (piece, cuts) in self.pieces.iter().zip(&placement.pieces) {
            let Some(cuts) = cuts else {
                continue;
            };
            let bytes = piece.rewritten(cuts, handles);
            let Some(at) = piece.item else {
                return Value::Array(bytes.into_iter().map(Value::from).collect());
            };
            if let (Some(slot), Some(item)) = (rewritten.get_mut(at), items.get(at)) {
                *slot = Some((!cuts.is_empty()).then(|| item_of(item, bytes)));
            }
        }
        let mut out = Vec::with_capacity(items.len());
        for (item, slot) in items.iter().zip(rewritten) {
            match slot {
                Some(Some(value)) => out.push(value),
                Some(None) => {}
                None => out.push(item.clone()),
            }
        }
        Value::Array(out)
    }
}

impl ArrayPiece {
    /// The bytes that write the run `text` of the array's text in this piece:
    /// `None` when its ends sit inside a replacement character, or a string's
    /// run would be no UTF-8.
    fn kept(&self, text: Range<usize>) -> Option<Range<usize>> {
        let start = byte_offset(&self.bytes, text.start.checked_sub(self.text.start)?)?;
        let end = byte_offset(&self.bytes, text.end.checked_sub(self.text.start)?)?;
        let run = self.bytes.get(start..end)?;
        if self.string && std::str::from_utf8(run).is_err() {
            return None;
        }
        Some(start..end)
    }

    /// This piece's bytes as `cuts` write them.
    fn rewritten(&self, cuts: &[Cut], handles: &[String]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for cut in cuts {
            match cut {
                Cut::Keep(run) => {
                    bytes.extend_from_slice(self.bytes.get(run.clone()).unwrap_or_default())
                }
                Cut::Handle(place) => {
                    bytes.extend_from_slice(handles.get(*place).map_or(&[][..], String::as_bytes));
                }
            }
        }
        bytes
    }
}

/// An array item of the same kind as `item` that holds `bytes`.
fn item_of(item: &Value, bytes: Vec<u8>) -> Value {
    match item {
        Value::String(_) => String::from_utf8(bytes)
            .map_or_else(|error| Value::Binary(error.into_bytes()), Value::from),
        Value::Ext(kind, _) => Value::Ext(*kind, bytes),
        Value::Array(_) => Value::Array(bytes.into_iter().map(Value::from).collect()),
        _ => Value::Binary(bytes),
    }
}

/// Where the offset `at` of `bytes`' lossy text sits in `bytes`: `None` inside
/// a replacement character.
fn byte_offset(bytes: &[u8], at: usize) -> Option<usize> {
    let (mut text, mut byte) = (0, 0);
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid().len();
        if at <= text + valid {
            return Some(byte + at - text);
        }
        text += valid;
        byte += valid;
        if !chunk.invalid().is_empty() {
            text += char::REPLACEMENT_CHARACTER.len_utf8();
            byte += chunk.invalid().len();
            if at < text {
                return None;
            }
        }
    }
    (at == text).then_some(byte)
}

/// How the door reads a body's parts for a recovery phrase spread over them
/// once each part is masked.
#[derive(Clone, Copy)]
pub(super) enum Spread {
    /// Its texts, one per line at any depth, as the door's whole read reads
    /// a body (one word per nested item).
    Leaves,
    /// Its MessagePack encoding's lossy text, as the text rules read a body's
    /// raw bytes (one word per 64-bit number, or between nested arrays'
    /// headers).
    Encoded,
}

impl Spread {
    /// Each recovery phrase `parts`, one after another, hold in this reading,
    /// in order: its words, one space between them.
    pub(super) fn phrases(self, parts: &[Value]) -> Vec<Zeroizing<Vec<u8>>> {
        let text = match self {
            Self::Leaves => {
                let mut text = Zeroizing::new(String::new());
                for part in parts {
                    super::super::whole_read::messagepack_leaves(part, &mut text);
                }
                text
            }
            Self::Encoded => {
                let mut bytes = Zeroizing::new(Vec::new());
                for part in parts {
                    if rmpv::encode::write_value(&mut *bytes, part).is_err() {
                        return Vec::new();
                    }
                }
                lossy(&bytes)
            }
        };
        phrases_in(&text)
            .into_iter()
            .map(|(phrase, _)| phrase)
            .collect()
    }

    /// The smallest part of `value` that holds, in this reading, a recovery
    /// phrase `places` takes: its path (an array item by its index, a map's
    /// key at `2i` and its member at `2i + 1`), and the phrase. A phrase
    /// `places` refuses is read past (REVIEW-7060 P1).
    pub(super) fn smallest_part(
        self,
        value: &Value,
        places: impl Fn(&[u8]) -> bool,
    ) -> Option<(Vec<usize>, Zeroizing<Vec<u8>>)> {
        let placed = |part: &Value| {
            self.phrases(std::slice::from_ref(part))
                .into_iter()
                .find(|phrase| places(phrase))
        };
        let mut phrase = placed(value)?;
        let mut path = Vec::new();
        let mut part = value;
        'descend: loop {
            let children: Vec<&Value> = match part {
                Value::Array(items) => items.iter().collect(),
                Value::Map(fields) => fields
                    .iter()
                    .flat_map(|(key, member)| [key, member])
                    .collect(),
                _ => break,
            };
            for (at, child) in children.into_iter().enumerate() {
                if let Some(found) = placed(child) {
                    phrase = found;
                    path.push(at);
                    part = child;
                    continue 'descend;
                }
            }
            break;
        }
        Some((path, phrase))
    }

    /// The smallest run of `items` that holds `phrase` in this reading and
    /// no other phrase: the items that take its handle, the rest kept as
    /// written (REVIEW-7060 P1). `None` when no run holds it alone. Each end
    /// is found by halving (speed).
    pub(super) fn run(self, items: &[Value], phrase: &[u8]) -> Option<Range<usize>> {
        let holds = |run: Range<usize>| {
            items.get(run).is_some_and(|run| {
                self.phrases(run)
                    .iter()
                    .any(|found| found.as_slice() == phrase)
            })
        };
        if !holds(0..items.len()) {
            return None;
        }
        // A run to the end holds it from `start`, and from `past` no more.
        let (mut start, mut past) = (0, items.len());
        while past - start > 1 {
            let mid = start + (past - start) / 2;
            if holds(mid..items.len()) {
                start = mid;
            } else {
                past = mid;
            }
        }
        // A run from `start` holds it to `end`, and to `short` not yet.
        let (mut short, mut end) = (start, items.len());
        while end - short > 1 {
            let mid = short + (end - short) / 2;
            if holds(start..mid) {
                end = mid;
            } else {
                short = mid;
            }
        }
        self.holds_alone(items.get(start..end)?, phrase)
            .then_some(start..end)
    }

    /// Whether `parts`, one after another, hold `phrase` in this reading and
    /// no other phrase.
    pub(super) fn holds_alone(self, parts: &[Value], phrase: &[u8]) -> bool {
        matches!(self.phrases(parts).as_slice(), [only] if only.as_slice() == phrase)
    }
}

/// The bytes an array item's text reads, as the field walk joins it: a
/// string, binary or extension value, or an array of byte values.
fn item_bytes(item: &Value) -> Option<Zeroizing<Vec<u8>>> {
    match item {
        Value::String(text) => Some(Zeroizing::new(text.as_bytes().to_vec())),
        Value::Binary(bytes) | Value::Ext(_, bytes) => Some(Zeroizing::new(bytes.clone())),
        Value::Array(values) => byte_values(values.iter().map(Value::as_u64)).map(Zeroizing::new),
        _ => None,
    }
}

fn lossy(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(String::from_utf8_lossy(bytes).into_owned())
}

/// Each recovery phrase `text` holds, in order, each span once: its words,
/// one space between them, and its span.
fn phrases_in(text: &str) -> Vec<(Zeroizing<Vec<u8>>, Range<usize>)> {
    let mut spans = shapes::mnemonic_spans(text);
    spans.sort_by_key(|span| (span.start, span.end));
    spans.dedup();
    spans
        .into_iter()
        .filter_map(|span| {
            let mut value = Zeroizing::new(Vec::with_capacity(span.len()));
            for word in words_in(text.as_bytes(), &span) {
                if !value.is_empty() {
                    value.push(b' ');
                }
                value.extend_from_slice(text.as_bytes().get(word)?);
            }
            Some((value, span))
        })
        .collect()
}

/// `leaf` decoded as the door decodes a body (`decode_members`: JSON, else
/// one whole MessagePack value), with where each of its parts sits.
fn decoded(leaf: &[u8]) -> Option<(PlanTree, Node)> {
    if let Ok(value) = serde_json::from_slice::<Value>(leaf) {
        let tree = PlanTree(value);
        return json::node(leaf).map(|node| (tree, node));
    }
    let mut cursor = std::io::Cursor::new(leaf);
    let tree = PlanTree(rmpv::decode::read_value(&mut cursor).ok()?);
    if cursor.position() != leaf.len() as u64 {
        return None;
    }
    messagepack::node(leaf).map(|node| (tree, node))
}

/// Where one decoded part sits in the leaf.
enum Node {
    /// A string, binary or extension value: its payload's span, and whether
    /// those bytes are its value as written (a JSON string with an escape
    /// is not).
    Bytes {
        span: Range<usize>,
        as_written: bool,
    },
    /// An integer: the span of the bytes that write its value (a fixint's own
    /// byte, a wider integer's payload, a JSON number's characters).
    Number(Range<usize>),
    Array(Vec<Node>),
    Map(Vec<(Node, Node)>),
    /// Nil, a boolean or a float: no text.
    Other,
}

/// One decoded part, read as the write door's field walk reads it
/// (`sanitize_messagepack`): an array as one text, then item by item; a map
/// key and member by member; text as itself. A phrase the array's text
/// holds does not end the reading: one nested in an item is found too (a
/// word two readings find is placed once, `place_split_phrases`).
fn read_part(value: &Value, node: &Node, out: &mut Vec<SplitPhrase>) {
    match (value, node) {
        (Value::Array(items), Node::Array(nodes)) if items.len() == nodes.len() => {
            read_text(out, |text| text.push_array(items, nodes));
            for (item, node) in items.iter().zip(nodes) {
                read_part(item, node, out);
            }
        }
        (Value::Map(fields), Node::Map(nodes)) if fields.len() == nodes.len() => {
            for ((key, member), (key_node, member_node)) in fields.iter().zip(nodes) {
                read_part(key, key_node, out);
                read_part(member, member_node, out);
            }
        }
        _ => read_text(out, |text| text.push_part(value, node)),
    }
}

/// The phrases in the text `build` writes. The text is read once alone;
/// only when it holds a phrase is it written again, keeping where each
/// word's characters sit in the leaf (speed: a long text keeps no map).
fn read_text(out: &mut Vec<SplitPhrase>, build: impl Fn(&mut MappedText) -> bool) {
    let mut plain = MappedText::default();
    if !build(&mut plain) {
        return;
    }
    let spans = shapes::mnemonic_spans(&plain.text);
    if spans.is_empty() {
        return;
    }
    let phrases: Vec<Vec<Range<usize>>> = spans
        .iter()
        .map(|span| words_in(plain.text.as_bytes(), span))
        .collect();
    let mut keep: Vec<Range<usize>> = phrases.iter().flatten().cloned().collect();
    keep.sort_by_key(|word| word.start);
    keep.dedup();
    let mut mapped = MappedText {
        keep,
        ..MappedText::default()
    };
    build(&mut mapped);
    for words in phrases {
        let mut value = Zeroizing::new(Vec::with_capacity(
            words.iter().map(|word| word.len() + 1).sum(),
        ));
        let mut places = Vec::with_capacity(words.len());
        for word in &words {
            let (Some(span), Some(text)) = (mapped.leaf_span(word), plain.text.get(word.clone()))
            else {
                // A word with no place in the leaf leaves its phrase unplaced:
                // the door's refusal stands.
                places.clear();
                break;
            };
            if !value.is_empty() {
                value.push(b' ');
            }
            value.extend_from_slice(text.as_bytes());
            places.push(span);
        }
        if !places.is_empty() {
            out.push(SplitPhrase {
                value,
                words: places,
            });
        }
    }
}

/// The words of the phrase at `span` in `text`: each run of letters in it.
/// A phrase's span holds list words and separators only.
fn words_in(text: &[u8], span: &Range<usize>) -> Vec<Range<usize>> {
    let mut words = Vec::new();
    let mut at = span.start;
    while at < span.end {
        if text.get(at).is_some_and(u8::is_ascii_alphabetic) {
            let start = at;
            while at < span.end && text.get(at).is_some_and(u8::is_ascii_alphabetic) {
                at += 1;
            }
            words.push(start..at);
        } else {
            at += 1;
        }
    }
    words
}

/// Text a reading shows of a leaf. Once `keep` names the words to place, it
/// keeps the leaf bytes each piece of text over them stands for. The text is
/// wiped when it drops.
#[derive(Default)]
struct MappedText {
    text: Zeroizing<String>,
    /// The spans in the text whose pieces are kept, in order, apart.
    keep: Vec<Range<usize>>,
    /// The pieces over `keep`, in order.
    pieces: Vec<Piece>,
}

/// A piece of a mapped text: its span in the text and the leaf bytes it
/// stands for. A piece `as_written` is those bytes as they are, byte for
/// byte; any other stands for all of them at once.
struct Piece {
    text: Range<usize>,
    leaf: Range<usize>,
    as_written: bool,
}

impl MappedText {
    fn push_piece(&mut self, text: &str, leaf: Range<usize>, as_written: bool) {
        let start = self.text.len();
        self.text.push_str(text);
        let span = start..self.text.len();
        let at = self.keep.partition_point(|word| word.end <= span.start);
        if self.keep.get(at).is_some_and(|word| word.start < span.end) {
            self.pieces.push(Piece {
                text: span,
                leaf,
                as_written,
            });
        }
    }

    /// `bytes`, the leaf's own from `start`, read as `String::from_utf8_lossy`
    /// reads them: each invalid run one U+FFFD.
    fn push_bytes(&mut self, bytes: &[u8], start: usize) {
        let mut at = start;
        for chunk in bytes.utf8_chunks() {
            let valid = chunk.valid();
            if !valid.is_empty() {
                self.push_piece(valid, at..at + valid.len(), true);
                at += valid.len();
            }
            let invalid = chunk.invalid().len();
            if invalid > 0 {
                self.push_piece("\u{FFFD}", at..at + invalid, false);
                at += invalid;
            }
        }
    }

    /// A text part (a string, binary or extension value, or an array of
    /// byte values) as one text; `false` for any other part.
    fn push_part(&mut self, value: &Value, node: &Node) -> bool {
        let bytes = match (value, node) {
            (Value::Array(items), Node::Array(nodes)) => {
                return self.push_byte_values(items, nodes);
            }
            (Value::String(text), Node::Bytes { .. }) => text.as_bytes(),
            (Value::Binary(bytes) | Value::Ext(_, bytes), Node::Bytes { .. }) => bytes.as_slice(),
            _ => return false,
        };
        let Node::Bytes { span, as_written } = node else {
            return false;
        };
        if *as_written && bytes.len() == span.len() {
            self.push_bytes(bytes, span.start);
        } else {
            // An escaped JSON string's characters stand for its whole span.
            let text = Zeroizing::new(String::from_utf8_lossy(bytes).into_owned());
            self.push_piece(&text, span.clone(), false);
        }
        true
    }

    /// An array as one text, as the field walk reads it before its items:
    /// its byte values, or its text items one per line. `false` when it is
    /// neither, or has fewer than two text items (each is read alone).
    fn push_array(&mut self, items: &[Value], nodes: &[Node]) -> bool {
        if self.push_byte_values(items, nodes) {
            return true;
        }
        let texts = items
            .iter()
            .zip(nodes)
            .filter(|(item, node)| reads_as_text(item, node))
            .count();
        if texts < 2 {
            return false;
        }
        let mut first = true;
        for (item, node) in items.iter().zip(nodes) {
            if !reads_as_text(item, node) {
                continue;
            }
            if !first {
                self.text.push('\n');
            }
            first = false;
            self.push_part(item, node);
        }
        true
    }

    /// Every text `value` carries, each on a line of its own, in order, at
    /// any depth, as the door's whole read joins them
    /// (`whole_read::messagepack_leaves`).
    fn push_leaves(&mut self, value: &Value, node: &Node) {
        match (value, node) {
            (Value::String(_) | Value::Binary(_) | Value::Ext(..), Node::Bytes { .. }) => {
                self.push_part(value, node);
                self.text.push('\n');
            }
            (Value::Array(items), Node::Array(nodes)) if items.len() == nodes.len() => {
                if !items.is_empty() && self.push_byte_values(items, nodes) {
                    self.text.push('\n');
                    return;
                }
                for (item, node) in items.iter().zip(nodes) {
                    self.push_leaves(item, node);
                }
            }
            (Value::Map(fields), Node::Map(nodes)) if fields.len() == nodes.len() => {
                for ((key, member), (key_node, member_node)) in fields.iter().zip(nodes) {
                    self.push_leaves(key, key_node);
                    self.push_leaves(member, member_node);
                }
            }
            _ => {}
        }
    }

    /// An array of byte values as the text those bytes read as, each
    /// character standing for the numbers that write its bytes. `false`
    /// when an item is no byte value.
    fn push_byte_values(&mut self, items: &[Value], nodes: &[Node]) -> bool {
        let Some(bytes) = byte_values(items.iter().map(Value::as_u64)).map(Zeroizing::new) else {
            return false;
        };
        let mut numbers = Vec::with_capacity(nodes.len());
        for node in nodes {
            match node {
                Node::Number(span) => numbers.push(span.clone()),
                _ => return false,
            }
        }
        if numbers.len() != bytes.len() {
            return false;
        }
        let leaf = |at: usize, len: usize| match (numbers.get(at), numbers.get(at + len - 1)) {
            (Some(first), Some(last)) => first.start..last.end,
            _ => 0..0,
        };
        let mut at = 0;
        let mut buffer = [0u8; 4];
        for chunk in bytes.utf8_chunks() {
            for ch in chunk.valid().chars() {
                let len = ch.len_utf8();
                self.push_piece(ch.encode_utf8(&mut buffer), leaf(at, len), false);
                at += len;
            }
            let invalid = chunk.invalid().len();
            if invalid > 0 {
                self.push_piece("\u{FFFD}", leaf(at, invalid), false);
                at += invalid;
            }
        }
        buffer.fill(0);
        true
    }

    /// The leaf span the text's `word` stands for: from its first byte's
    /// place to its last's, the separators between included.
    fn leaf_span(&self, word: &Range<usize>) -> Option<Range<usize>> {
        let first = self
            .pieces
            .partition_point(|piece| piece.text.end <= word.start);
        let mut span: Option<Range<usize>> = None;
        for piece in self
            .pieces
            .get(first..)?
            .iter()
            .take_while(|piece| piece.text.start < word.end)
        {
            let leaf = if piece.as_written {
                let from = word.start.max(piece.text.start) - piece.text.start;
                let to = word.end.min(piece.text.end) - piece.text.start;
                piece.leaf.start + from..piece.leaf.start + to
            } else {
                piece.leaf.clone()
            };
            span = Some(match span {
                Some(held) => held.start.min(leaf.start)..held.end.max(leaf.end),
                None => leaf,
            });
        }
        span.filter(|span| !span.is_empty())
    }
}

/// Whether the field walk reads `item` as one of an array's text items: a
/// string, binary or extension value, or an array of byte values.
fn reads_as_text(item: &Value, node: &Node) -> bool {
    match (item, node) {
        (Value::String(_) | Value::Binary(_) | Value::Ext(..), Node::Bytes { .. }) => true,
        (Value::Array(values), Node::Array(nodes)) => {
            values.len() == nodes.len()
                && values
                    .iter()
                    .all(|value| value.as_u64().is_some_and(|n| n <= 0xff))
                && nodes.iter().all(|node| matches!(node, Node::Number(_)))
        }
        _ => false,
    }
}

/// `leaf` with each of `marks` filled where the door's decoder still reads
/// it as it reads `leaf` (REVIEW-7059 P1): in a string, binary or extension
/// value each byte a mark covers is the mask's filler (a character's bytes
/// whole, an escaped JSON string's whole text), a number a mark touches
/// writes zero, and the frames between parts stay as written. `None` when
/// the door decodes `leaf` as neither JSON nor one MessagePack value: it
/// reads that leaf, and the leaf filled, as text alone.
pub(super) fn filled_in_place(leaf: &[u8], marks: &[Range<usize>]) -> Option<Zeroizing<Vec<u8>>> {
    let (_, node) = decoded(leaf)?;
    // `decoded` takes JSON first.
    let json = serde_json::from_slice::<Value>(leaf).map(PlanTree).is_ok();
    let mut copy = Zeroizing::new(leaf.to_vec());
    fill_in_place(&node, json, leaf, marks, &mut copy);
    Some(copy)
}

/// [`filled_in_place`] over one part and each part under it.
fn fill_in_place(node: &Node, json: bool, leaf: &[u8], marks: &[Range<usize>], copy: &mut [u8]) {
    let touches = |part: &Range<usize>| {
        marks
            .iter()
            .any(|mark| mark.start < part.end && part.start < mark.end)
    };
    match node {
        Node::Bytes { span, as_written } => {
            if !touches(span) {
                return;
            }
            if !*as_written {
                // An escape is filled whole: the string's whole text.
                fill(copy, span.clone(), FILLER);
                return;
            }
            for mark in marks {
                let mut part = mark.start.max(span.start)..mark.end.min(span.end);
                if part.is_empty() {
                    continue;
                }
                // A character's bytes are filled whole, so text stays text.
                while part.start > span.start && leaf.get(part.start).is_some_and(continues_char) {
                    part.start -= 1;
                }
                while part.end < span.end && leaf.get(part.end).is_some_and(continues_char) {
                    part.end += 1;
                }
                fill(copy, part, FILLER);
            }
        }
        Node::Number(span) => {
            if !touches(span) {
                return;
            }
            if json {
                // A zero, then blanks to the number's width.
                fill(copy, span.clone(), b' ');
                fill(copy, span.start..span.start + 1, b'0');
            } else {
                fill(copy, span.clone(), 0);
            }
        }
        Node::Array(items) => {
            for item in items {
                fill_in_place(item, json, leaf, marks, copy);
            }
        }
        Node::Map(fields) => {
            for (key, member) in fields {
                fill_in_place(key, json, leaf, marks, copy);
                fill_in_place(member, json, leaf, marks, copy);
            }
        }
        Node::Other => {}
    }
}

fn fill(copy: &mut [u8], span: Range<usize>, byte: u8) {
    if let Some(bytes) = copy.get_mut(span) {
        bytes.fill(byte);
    }
}

/// Whether `byte` continues a UTF-8 character.
fn continues_char(byte: &u8) -> bool {
    byte & 0xc0 == 0x80
}

/// Where each part of a JSON text sits. serde_json read the text whole
/// first, so it is valid JSON.
mod json {
    use super::Node;

    pub(super) fn node(text: &[u8]) -> Option<Node> {
        let mut at = 0;
        value(text, &mut at)
    }

    fn value(text: &[u8], at: &mut usize) -> Option<Node> {
        skip_blanks(text, at);
        let start = *at;
        match *text.get(start)? {
            b'{' => {
                *at += 1;
                let mut fields = Vec::new();
                if next_is(text, at, b'}') {
                    return Some(Node::Map(fields));
                }
                loop {
                    let key = value(text, at)?;
                    if !next_is(text, at, b':') {
                        return None;
                    }
                    fields.push((key, value(text, at)?));
                    if next_is(text, at, b'}') {
                        return Some(Node::Map(fields));
                    }
                    if !next_is(text, at, b',') {
                        return None;
                    }
                }
            }
            b'[' => {
                *at += 1;
                let mut items = Vec::new();
                if next_is(text, at, b']') {
                    return Some(Node::Array(items));
                }
                loop {
                    items.push(value(text, at)?);
                    if next_is(text, at, b']') {
                        return Some(Node::Array(items));
                    }
                    if !next_is(text, at, b',') {
                        return None;
                    }
                }
            }
            b'"' => {
                let content = start + 1;
                let mut end = content;
                let mut as_written = true;
                loop {
                    match *text.get(end)? {
                        b'"' => break,
                        b'\\' => {
                            as_written = false;
                            end += 2;
                        }
                        _ => end += 1,
                    }
                }
                *at = end + 1;
                Some(Node::Bytes {
                    span: content..end,
                    as_written,
                })
            }
            b'-' | b'0'..=b'9' => {
                while text.get(*at).is_some_and(|byte| {
                    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                }) {
                    *at += 1;
                }
                Some(Node::Number(start..*at))
            }
            b't' | b'n' => {
                *at += 4;
                Some(Node::Other)
            }
            b'f' => {
                *at += 5;
                Some(Node::Other)
            }
            _ => None,
        }
    }

    /// Skips blanks, then takes `byte` if it comes next.
    fn next_is(text: &[u8], at: &mut usize, byte: u8) -> bool {
        skip_blanks(text, at);
        let next = text.get(*at) == Some(&byte);
        if next {
            *at += 1;
        }
        next
    }

    fn skip_blanks(text: &[u8], at: &mut usize) {
        while matches!(text.get(*at), Some(b' ' | b'\n' | b'\t' | b'\r')) {
            *at += 1;
        }
    }
}

/// Where each part of one whole MessagePack value sits. rmpv read the bytes
/// whole first, so the value is well formed.
mod messagepack {
    use super::Node;

    pub(super) fn node(bytes: &[u8]) -> Option<Node> {
        let mut at = 0;
        let node = value(bytes, &mut at)?;
        (at == bytes.len()).then_some(node)
    }

    fn value(bytes: &[u8], at: &mut usize) -> Option<Node> {
        let marker = *take(bytes, at, 1)?.first()?;
        Some(match marker {
            0x00..=0x7f | 0xe0..=0xff => Node::Number(*at - 1..*at),
            0x80..=0x8f => map(bytes, at, usize::from(marker & 0x0f))?,
            0x90..=0x9f => array(bytes, at, usize::from(marker & 0x0f))?,
            0xa0..=0xbf => payload(bytes, at, usize::from(marker & 0x1f))?,
            0xc0 | 0xc2 | 0xc3 => Node::Other,
            0xc4 | 0xd9 => {
                let len = length(bytes, at, 1)?;
                payload(bytes, at, len)?
            }
            0xc5 | 0xda => {
                let len = length(bytes, at, 2)?;
                payload(bytes, at, len)?
            }
            0xc6 | 0xdb => {
                let len = length(bytes, at, 4)?;
                payload(bytes, at, len)?
            }
            0xc7..=0xc9 => {
                let len = length(bytes, at, 1 << (marker - 0xc7))?;
                take(bytes, at, 1)?;
                payload(bytes, at, len)?
            }
            0xca => {
                take(bytes, at, 4)?;
                Node::Other
            }
            0xcb => {
                take(bytes, at, 8)?;
                Node::Other
            }
            0xcc..=0xcf => number(bytes, at, 1 << (marker - 0xcc))?,
            0xd0..=0xd3 => number(bytes, at, 1 << (marker - 0xd0))?,
            0xd4..=0xd8 => {
                take(bytes, at, 1)?;
                payload(bytes, at, 1 << (marker - 0xd4))?
            }
            0xdc => {
                let len = length(bytes, at, 2)?;
                array(bytes, at, len)?
            }
            0xdd => {
                let len = length(bytes, at, 4)?;
                array(bytes, at, len)?
            }
            0xde => {
                let len = length(bytes, at, 2)?;
                map(bytes, at, len)?
            }
            0xdf => {
                let len = length(bytes, at, 4)?;
                map(bytes, at, len)?
            }
            0xc1 => return None,
        })
    }

    fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Option<&'a [u8]> {
        let end = at.checked_add(len)?;
        let taken = bytes.get(*at..end)?;
        *at = end;
        Some(taken)
    }

    /// A big-endian length `width` bytes wide.
    fn length(bytes: &[u8], at: &mut usize, width: usize) -> Option<usize> {
        take(bytes, at, width)?
            .iter()
            .try_fold(0usize, |len, &byte| {
                len.checked_mul(256)?.checked_add(usize::from(byte))
            })
    }

    fn payload(bytes: &[u8], at: &mut usize, len: usize) -> Option<Node> {
        let start = *at;
        take(bytes, at, len)?;
        Some(Node::Bytes {
            span: start..*at,
            as_written: true,
        })
    }

    fn number(bytes: &[u8], at: &mut usize, width: usize) -> Option<Node> {
        let start = *at;
        take(bytes, at, width)?;
        Some(Node::Number(start..*at))
    }

    /// `len` items, each read in turn: every item takes a byte at least, so
    /// a length past the bytes ends at their end.
    fn array(bytes: &[u8], at: &mut usize, len: usize) -> Option<Node> {
        let mut items = Vec::new();
        for _ in 0..len {
            items.push(value(bytes, at)?);
        }
        Some(Node::Array(items))
    }

    fn map(bytes: &[u8], at: &mut usize, len: usize) -> Option<Node> {
        let mut fields = Vec::new();
        for _ in 0..len {
            let key = value(bytes, at)?;
            fields.push((key, value(bytes, at)?));
        }
        Some(Node::Map(fields))
    }
}
