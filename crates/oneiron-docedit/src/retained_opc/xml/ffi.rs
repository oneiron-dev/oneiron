//! Minimal Expat C ABI. `expat-sys` links system Expat where present and
//! builds its bundled library otherwise. Keep every unsafe operation here or
//! at a callback with a local SAFETY proof.
use std::ffi::{c_char, c_int, c_long, c_void};
pub(super) type Parser = *mut c_void;
#[link(name = "expat")]
unsafe extern "C" {
    pub(super) fn XML_ParserCreateNS(encoding: *const c_char, separator: c_char) -> Parser;
    pub(super) fn XML_ParserFree(parser: Parser);
    pub(super) fn XML_SetUserData(parser: Parser, data: *mut c_void);
    pub(super) fn XML_SetXmlDeclHandler(
        parser: Parser,
        handler: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, c_int)>,
    );
    pub(super) fn XML_SetElementHandler(
        parser: Parser,
        start: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const *const c_char)>,
        end: Option<unsafe extern "C" fn(*mut c_void, *const c_char)>,
    );
    pub(super) fn XML_SetCharacterDataHandler(
        parser: Parser,
        handler: Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int)>,
    );
    pub(super) fn XML_SetCommentHandler(
        parser: Parser,
        handler: Option<unsafe extern "C" fn(*mut c_void, *const c_char)>,
    );
    pub(super) fn XML_SetProcessingInstructionHandler(
        parser: Parser,
        handler: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char)>,
    );
    pub(super) fn XML_SetCdataSectionHandler(
        parser: Parser,
        start: Option<unsafe extern "C" fn(*mut c_void)>,
        end: Option<unsafe extern "C" fn(*mut c_void)>,
    );
    pub(super) fn XML_SetStartDoctypeDeclHandler(
        parser: Parser,
        handler: Option<
            unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, *const c_char, c_int),
        >,
    );
    pub(super) fn XML_SetExternalEntityRefHandler(
        parser: Parser,
        handler: Option<
            unsafe extern "C" fn(
                Parser,
                *const c_char,
                *const c_char,
                *const c_char,
                *const c_char,
            ) -> c_int,
        >,
    );
    pub(super) fn XML_SetParamEntityParsing(parser: Parser, parsing: c_int) -> c_int;
    pub(super) fn XML_Parse(parser: Parser, input: *const c_char, len: c_int, last: c_int)
    -> c_int;
    pub(super) fn XML_GetCurrentByteIndex(parser: Parser) -> c_long;
    pub(super) fn XML_StopParser(parser: Parser, resumable: c_int) -> c_int;
}

pub(super) struct OwnedParser(pub(super) Parser);
impl Drop for OwnedParser {
    fn drop(&mut self) {
        // SAFETY: `OwnedParser` is the unique owner of a non-null Expat parser;
        // callbacks finish before the owner leaves the parse function.
        unsafe { XML_ParserFree(self.0) };
    }
}
