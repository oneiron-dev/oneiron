//! One authoritative parse. Expat validates XML 1.0 and Namespaces, and its
//! source indices refer to exactly the bytes retained by this part (BOM too).
use super::ffi::{self, OwnedParser};
use crate::retained_opc::{Error, Result};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ops::Range,
};

/// Caller-resolved XML limits. No parser-owned or hardcoded fallback budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
}

#[derive(Debug)]
pub(super) struct Node<'a> {
    pub name: &'a str,
    pub parent: Option<usize>,
    pub inner: Range<usize>,
    pub value: String,
    pub children: bool,
    pub mixed: bool,
    pub empty: bool,
}

/// Validated source and source-indexed arena; only this private constructor
/// can mint checked text targets. IDs here are local arena indices, not model IDs.
pub(in crate::retained_opc) struct ValidatedXmlPart<'a> {
    pub(super) source: &'a [u8],
    pub(super) nodes: Vec<Node<'a>>,
    pub(super) signature: bool,
    pub(super) limits: XmlLimits,
}

struct State<'a> {
    source: &'a [u8],
    limits: XmlLimits,
    parser: ffi::Parser,
    nodes: Vec<Node<'a>>,
    events: usize,
    stack: Vec<usize>,
    signature: bool,
    error: Option<&'static str>,
}

impl State<'_> {
    fn reject(&mut self, why: &'static str) {
        self.error = Some(why);
        // SAFETY: parser remains live throughout XML_Parse and this callback.
        unsafe { ffi::XML_StopParser(self.parser, 0) };
    }
    fn position(&self) -> Option<usize> {
        // SAFETY: parser remains live during its callback.
        let index = unsafe { ffi::XML_GetCurrentByteIndex(self.parser) };
        usize::try_from(index)
            .ok()
            .filter(|&at| at <= self.source.len())
    }
    fn consume_node(&mut self) -> Result<()> {
        self.events = self
            .events
            .checked_add(1)
            .ok_or(Error::Edit("XML node limit"))?;
        if self.events > self.limits.max_nodes {
            return Err(Error::Edit("XML node limit"));
        }
        Ok(())
    }
    fn open(&mut self, at: usize, attrs: *const *const c_char) -> Result<()> {
        self.consume_node()?;
        if self.stack.len() >= self.limits.max_depth {
            return Err(Error::Edit("XML depth limit"));
        }
        if self.nodes.len() >= self.limits.max_nodes {
            return Err(Error::Edit("XML node limit"));
        }
        let (name, inner, empty) = source_start(self.source, at)?;
        let parent = self.stack.last().copied();
        if let Some(id) = parent {
            self.nodes[id].children = true;
        }
        let index = self.nodes.len();
        self.nodes.push(Node {
            name,
            parent,
            inner: inner..inner,
            value: String::new(),
            children: false,
            mixed: false,
            empty,
        });
        self.stack.push(index);
        if attrs.is_null() {
            return Err(Error::Edit("invalid XML attributes"));
        }
        let mut i = 0usize;
        // Attribute pairs are NUL-terminated by Expat. The source byte limit
        // bounds their count even when an attacker uses many short attributes.
        while i < self.source.len() {
            // SAFETY: Expat supplies an array of NUL-terminated name/value
            // pairs followed by a null name. We only walk until that null.
            let name_ptr = unsafe { *attrs.add(i) };
            if name_ptr.is_null() {
                return Ok(());
            }
            // SAFETY: a non-null name has a paired non-null value by the
            // Expat start-element callback contract.
            let value_ptr = unsafe { *attrs.add(i + 1) };
            if value_ptr.is_null() {
                return Err(Error::Edit("invalid XML attribute"));
            }
            // SAFETY: both pointers refer to Expat-owned NUL-terminated UTF-8
            // callback strings and are read only while the callback is active.
            let key = unsafe { CStr::from_ptr(name_ptr) }
                .to_str()
                .map_err(|_| Error::Edit("invalid XML attribute"))?;
            // SAFETY: Expat owns the NUL-terminated value for this callback.
            let value = unsafe { CStr::from_ptr(value_ptr) }
                .to_str()
                .map_err(|_| Error::Edit("invalid XML attribute"))?;
            if matches!(key.rsplit('|').next(), Some("Type" | "ContentType"))
                && value.to_ascii_lowercase().contains("digital-signature")
            {
                self.signature = true;
            }
            i += 2;
        }
        Err(Error::Edit("XML attribute limit"))
    }
    fn close(&mut self, at: usize) -> Result<()> {
        let id = self.stack.pop().ok_or(Error::Edit("unbalanced XML"))?;
        let node = &mut self.nodes[id];
        if !node.empty {
            if self.source.get(at..at.saturating_add(2)) != Some(b"</") || at < node.inner.start {
                return Err(Error::Edit("invalid XML source span"));
            }
            node.inner.end = at;
        }
        Ok(())
    }
    fn characters(&mut self, data: *const c_char, count: c_int) -> Result<()> {
        self.consume_node()?;
        let count = usize::try_from(count).map_err(|_| Error::Edit("invalid XML text"))?;
        if count == 0 {
            return Ok(());
        }
        let id = self
            .stack
            .last()
            .copied()
            .ok_or(Error::Edit("text outside XML root"))?;
        if count > self.source.len().saturating_sub(self.nodes[id].value.len()) {
            return Err(Error::Edit("XML text expansion limit"));
        }
        // SAFETY: Expat passes `count` readable UTF-8 bytes during this
        // callback; no pointer is retained after returning.
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), count) };
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Edit("invalid XML text"))?;
        self.nodes[id].value.push_str(text);
        Ok(())
    }
    fn mark_nontext(&mut self) {
        if self.error.is_some() {
            return;
        }
        if let Err(Error::Edit(why)) = self.consume_node() {
            self.reject(why);
            return;
        }
        if let Some(&id) = self.stack.last() {
            self.nodes[id].mixed = true;
        }
    }
}

/// Expat emits original-input byte positions. Find the end of one validated
/// start tag, honoring quoted `>` in attributes; do not reinterpret a second
/// token stream or trim a UTF-8 BOM from the original byte coordinates.
fn source_start(source: &[u8], at: usize) -> Result<(&str, usize, bool)> {
    if source.get(at) != Some(&b'<') {
        return Err(Error::Edit("invalid XML source index"));
    }
    let begin = at.checked_add(1).ok_or(Error::Edit("XML span overflow"))?;
    let name_end = source[begin..]
        .iter()
        .position(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'/' | b'>'))
        .and_then(|pos| begin.checked_add(pos))
        .ok_or(Error::Edit("invalid XML start tag"))?;
    let name = std::str::from_utf8(&source[begin..name_end])
        .map_err(|_| Error::Edit("invalid XML name"))?;
    let mut quote = None;
    for (i, &byte) in source[name_end..].iter().enumerate() {
        if quote == Some(byte) {
            quote = None;
        } else if quote.is_none() {
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
            } else if byte == b'>' {
                let offset = name_end + i;
                return Ok((
                    name,
                    offset + 1,
                    offset > name_end && source[offset - 1] == b'/',
                ));
            }
        }
    }
    Err(Error::Edit("unterminated XML start tag"))
}

// A callback never unwinds across C: all fallible work records a typed reason
// and aborts Expat. `State` has stable address until XML_Parse returns.
unsafe extern "C" fn start(user: *mut c_void, _: *const c_char, attrs: *const *const c_char) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    let state = unsafe { &mut *user.cast::<State<'_>>() };
    if state.error.is_some() {
        return;
    }
    match state
        .position()
        .ok_or(Error::Edit("XML index overflow"))
        .and_then(|at| state.open(at, attrs))
    {
        Ok(()) => {}
        Err(Error::Edit(why) | Error::Invalid(why)) => state.reject(why),
    }
}
unsafe extern "C" fn end(user: *mut c_void, _: *const c_char) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    let state = unsafe { &mut *user.cast::<State<'_>>() };
    if state.error.is_some() {
        return;
    }
    match state
        .position()
        .ok_or(Error::Edit("XML index overflow"))
        .and_then(|at| state.close(at))
    {
        Ok(()) => {}
        Err(Error::Edit(why) | Error::Invalid(why)) => state.reject(why),
    }
}
unsafe extern "C" fn characters(user: *mut c_void, data: *const c_char, count: c_int) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    let state = unsafe { &mut *user.cast::<State<'_>>() };
    if state.error.is_some() {
        return;
    }
    if let Err(Error::Edit(why) | Error::Invalid(why)) = state.characters(data, count) {
        state.reject(why);
    }
}
unsafe extern "C" fn nontext(user: *mut c_void, _: *const c_char) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    unsafe { &mut *user.cast::<State<'_>>() }.mark_nontext();
}
unsafe extern "C" fn pi(user: *mut c_void, _: *const c_char, _: *const c_char) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    unsafe { &mut *user.cast::<State<'_>>() }.mark_nontext();
}
unsafe extern "C" fn cdata(user: *mut c_void) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    unsafe { &mut *user.cast::<State<'_>>() }.mark_nontext();
}
unsafe extern "C" fn declaration(
    user: *mut c_void,
    version: *const c_char,
    encoding: *const c_char,
    _: c_int,
) {
    // SAFETY: Expat calls synchronously with a live State and valid C strings.
    let state = unsafe { &mut *user.cast::<State<'_>>() };
    if version.is_null() {
        state.reject("unsupported XML version");
        return;
    }
    // SAFETY: Expat provides a live NUL-terminated version for this callback.
    let version = unsafe { CStr::from_ptr(version) }.to_bytes();
    if version != b"1.0" {
        state.reject("unsupported XML version");
    } else if !encoding.is_null() {
        // SAFETY: a non-null Expat encoding is NUL-terminated and live here.
        let encoding = unsafe { CStr::from_ptr(encoding) }.to_bytes();
        if !encoding.eq_ignore_ascii_case(b"UTF-8") {
            state.reject("unsupported XML encoding");
        }
    }
}
unsafe extern "C" fn refuse_external_entity(
    _: ffi::Parser,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
) -> c_int {
    0 // No external fetch or entity parser is ever created.
}
unsafe extern "C" fn doctype(
    user: *mut c_void,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: c_int,
) {
    // SAFETY: user_data is set to a live, exclusive State for this parser.
    unsafe { &mut *user.cast::<State<'_>>() }.reject("DTD is not supported");
}

impl<'a> ValidatedXmlPart<'a> {
    pub(in crate::retained_opc) fn parse(source: &'a [u8], limits: XmlLimits) -> Result<Self> {
        if limits.max_depth == 0 || limits.max_nodes == 0 {
            return Err(Error::Edit("XML limits must be positive"));
        }
        std::str::from_utf8(source).map_err(|_| Error::Edit("non-UTF8 XML"))?;
        let size =
            c_int::try_from(source.len()).map_err(|_| Error::Edit("XML input size limit"))?;
        // A non-null native parser lives through XML_Parse and is freed by
        // OwnedParser even if validation refuses the part.
        // SAFETY: constant is a NUL-terminated encoding label for Expat.
        let ptr = unsafe { ffi::XML_ParserCreateNS(c"UTF-8".as_ptr(), b'|' as c_char) };
        if ptr.is_null() {
            return Err(Error::Edit("XML parser unavailable"));
        }
        let parser = OwnedParser(ptr);
        let mut state = State {
            source,
            limits,
            parser: parser.0,
            nodes: Vec::new(),
            events: 0,
            stack: Vec::new(),
            signature: false,
            error: None,
        };
        // SAFETY: callbacks borrow `state` only while this synchronous parse
        // executes. Expat owns `parser` exclusively until OwnedParser drops.
        let result = unsafe {
            ffi::XML_SetUserData(parser.0, (&raw mut state).cast());
            ffi::XML_SetXmlDeclHandler(parser.0, Some(declaration));
            ffi::XML_SetElementHandler(parser.0, Some(start), Some(end));
            ffi::XML_SetCharacterDataHandler(parser.0, Some(characters));
            ffi::XML_SetCommentHandler(parser.0, Some(nontext));
            ffi::XML_SetProcessingInstructionHandler(parser.0, Some(pi));
            ffi::XML_SetCdataSectionHandler(parser.0, Some(cdata), None);
            ffi::XML_SetStartDoctypeDeclHandler(parser.0, Some(doctype));
            ffi::XML_SetExternalEntityRefHandler(parser.0, Some(refuse_external_entity));
            ffi::XML_SetParamEntityParsing(parser.0, 0);
            ffi::XML_Parse(parser.0, source.as_ptr().cast(), size, 1)
        };
        if let Some(why) = state.error {
            return Err(Error::Edit(why));
        }
        if result != 1 || !state.stack.is_empty() || state.nodes.is_empty() {
            return Err(Error::Edit("malformed or unsupported XML"));
        }
        Ok(Self {
            source,
            nodes: state.nodes,
            signature: state.signature,
            limits,
        })
    }
    pub(in crate::retained_opc) fn signature(&self) -> bool {
        self.signature
    }
}
