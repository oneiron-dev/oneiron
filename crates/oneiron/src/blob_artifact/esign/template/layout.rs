//! Deterministic paginated HTML flow; fixed PDF standard fonts and no host state.
use super::*;
use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};

#[derive(Clone, Copy)]
pub(super) struct Style {
    pub(super) size: f64,
    pub(super) bold: bool,
    pub(super) italic: bool,
    pub(super) color: [f64; 3],
    pub(super) align: u8,
    pub(super) pre: bool,
}
impl Default for Style {
    fn default() -> Self {
        Self {
            size: 11.,
            bold: false,
            italic: false,
            color: [0.; 3],
            align: 0,
            pre: false,
        }
    }
}
struct Run {
    text: Vec<u8>,
    style: Style,
    x: f64,
}
pub(super) struct Flow {
    pub(super) page: TemplatePage,
    pub(super) pages: Vec<Vec<Operation>>,
    pub(super) y: f64,
    line: Vec<Run>,
    x: f64,
    line_height: f64,
    space: bool,
    op_count: usize,
}
impl Flow {
    pub(super) fn new(page: TemplatePage) -> Self {
        Self {
            page,
            pages: vec![Vec::new()],
            y: page.margin,
            line: Vec::new(),
            x: 0.,
            line_height: 0.,
            space: false,
            op_count: 0,
        }
    }
    pub(super) fn width(&self) -> f64 {
        self.page.width - 2. * self.page.margin
    }
    pub(super) fn page_break(&mut self) -> Result<()> {
        self.flush()?;
        if self.y > self.page.margin {
            if self.pages.len() >= 1000 {
                return Err(ContentTemplateError::Limit);
            }
            self.pages.push(Vec::new());
            self.y = self.page.margin;
        }
        Ok(())
    }
    pub(super) fn gap(&mut self, amount: f64) -> Result<()> {
        self.flush()?;
        if amount < 0. || amount > self.page.height {
            return Err(ContentTemplateError::Geometry);
        }
        if self.y + amount > self.page.height - self.page.margin {
            self.page_break()?;
        }
        self.y += amount;
        Ok(())
    }
    pub(super) fn text(&mut self, text: &str, style: Style) -> Result<()> {
        if style.pre {
            self.space = false;
            let normalized = text
                .replace("\r\n", "\n")
                .replace('\r', "\n")
                .replace('\t', "    ");
            let mut lines = normalized.split('\n').peekable();
            while let Some(line) = lines.next() {
                self.word(line, style)?;
                if lines.peek().is_some() {
                    if self.line.is_empty() {
                        self.gap(style.size * 1.3)?;
                    } else {
                        self.flush()?;
                    }
                }
            }
            return Ok(());
        }
        let mut word = String::new();
        for ch in text.chars() {
            if ch.is_whitespace() && ch != '\u{a0}' {
                self.word(&word, style)?;
                word.clear();
                self.space = true;
            } else {
                word.push(ch);
            }
        }
        self.word(&word, style)
    }
    fn word(&mut self, text: &str, style: Style) -> Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        let (bytes, _, unmappable) = encoding_rs::WINDOWS_1252.encode(text);
        if unmappable || text.chars().any(char::is_control) {
            return Err(ContentTemplateError::Font);
        }
        let cell = style.size * 0.6;
        for chunk in bytes.chunks(((self.width() / cell).floor() as usize).max(1)) {
            let width = chunk.len() as f64 * cell;
            let space = if self.space && self.x > 0. { cell } else { 0. };
            if self.x + space + width > self.width() + 0.001 {
                self.flush()?;
            }
            if width > self.width() + 0.001 {
                return Err(ContentTemplateError::Overflow);
            }
            let mut text = chunk.to_vec();
            if self.space && self.x > 0. {
                text.insert(0, b' ');
            }
            let advance = text.len() as f64 * cell;
            self.line.push(Run {
                text,
                style,
                x: self.x,
            });
            self.x += advance;
            self.line_height = self.line_height.max(style.size * 1.3);
            self.space = false;
        }
        Ok(())
    }
    pub(super) fn flush(&mut self) -> Result<()> {
        if self.line.is_empty() {
            self.space = false;
            return Ok(());
        }
        if self.y + self.line_height > self.page.height - self.page.margin {
            if self.pages.len() >= 1000 {
                return Err(ContentTemplateError::Limit);
            }
            self.pages.push(Vec::new());
            self.y = self.page.margin;
        }
        if self.line_height > self.page.height - 2. * self.page.margin {
            return Err(ContentTemplateError::Overflow);
        }
        self.op_count += self.line.len() * 5 + 2;
        if self.op_count > 250_000 {
            return Err(ContentTemplateError::Limit);
        }
        let align = self.line.first().map(|r| r.style.align).unwrap_or(0);
        let shift = match align {
            1 => (self.width() - self.x) / 2.,
            2 => self.width() - self.x,
            _ => 0.,
        };
        let ops = self
            .pages
            .last_mut()
            .ok_or(ContentTemplateError::Overflow)?;
        op(ops, "BT", &[]);
        for run in self.line.drain(..) {
            let style = run.style;
            let name = match (style.bold, style.italic) {
                (false, false) => "F0",
                (true, false) => "F1",
                (false, true) => "F2",
                (true, true) => "F3",
            };
            op(ops, "rg", &style.color);
            ops.push(Operation::new(
                "Tf",
                vec![
                    Object::Name(name.as_bytes().to_vec()),
                    Object::Real(style.size as f32),
                ],
            ));
            op(
                ops,
                "Tm",
                &[
                    1.,
                    0.,
                    0.,
                    1.,
                    self.page.margin + run.x + shift,
                    self.page.height - self.y - style.size,
                ],
            );
            ops.push(Operation::new(
                "Tj",
                vec![Object::String(run.text, lopdf::StringFormat::Literal)],
            ));
        }
        op(ops, "ET", &[]);
        self.y += self.line_height;
        self.x = 0.;
        self.line_height = 0.;
        self.space = false;
        Ok(())
    }
    pub(super) fn rule(&mut self) -> Result<()> {
        self.gap(6.)?;
        let width = self.width();
        let y = self.page.height - self.y;
        let ops = self
            .pages
            .last_mut()
            .ok_or(ContentTemplateError::Overflow)?;
        op(ops, "g", &[0.]);
        op(ops, "w", &[0.5]);
        op(ops, "m", &[self.page.margin, y]);
        op(ops, "l", &[self.page.margin + width, y]);
        op(ops, "S", &[]);
        self.gap(6.)
    }
    pub(super) fn table_row(&mut self, cells: Vec<Flow>) -> Result<()> {
        self.flush()?;
        if cells.is_empty() {
            return Ok(());
        }
        let height = cells.iter().map(|c| c.y + 6.).fold(0f64, f64::max);
        if height > self.page.height - 2. * self.page.margin {
            return Err(ContentTemplateError::Overflow);
        }
        if self.y + height > self.page.height - self.page.margin {
            self.page_break()?;
        }
        self.op_count += cells.iter().map(|c| c.op_count + 8).sum::<usize>();
        if self.op_count > 250_000 {
            return Err(ContentTemplateError::Limit);
        }
        let width = self.width() / cells.len() as f64;
        let ops = self
            .pages
            .last_mut()
            .ok_or(ContentTemplateError::Overflow)?;
        for (i, cell) in cells.into_iter().enumerate() {
            if cell.pages.len() != 1 {
                return Err(ContentTemplateError::Overflow);
            }
            let x = self.page.margin + i as f64 * width;
            op(ops, "q", &[]);
            op(ops, "cm", &[1., 0., 0., 1., x + 3., -self.y - 3.]);
            ops.extend(cell.pages.into_iter().flatten());
            op(ops, "Q", &[]);
            op(ops, "g", &[0.]);
            op(ops, "w", &[0.5]);
            op(
                ops,
                "re",
                &[x, self.page.height - self.y - height, width, height],
            );
            op(ops, "S", &[]);
        }
        self.y += height;
        Ok(())
    }
    pub(super) fn finish(mut self) -> Result<Vec<u8>> {
        self.flush()?;
        let mut doc = Document::with_version("1.7");
        doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
        let parent = doc.new_object_id();
        let mut fonts = Dictionary::new();
        for (i, font) in [
            "Courier",
            "Courier-Bold",
            "Courier-Oblique",
            "Courier-BoldOblique",
        ]
        .iter()
        .enumerate()
        {
            let id=doc.add_object(dictionary!{"Type"=>"Font","Subtype"=>"Type1","BaseFont"=>*font,"Encoding"=>"WinAnsiEncoding"});
            fonts.set(format!("F{i}"), id);
        }
        let mut kids = Vec::new();
        let mut total = 0;
        for ops in self.pages {
            let bytes = Content { operations: ops }
                .encode()
                .map_err(|_| ContentTemplateError::Overflow)?;
            total += bytes.len();
            if total > 16 * 1024 * 1024 {
                return Err(ContentTemplateError::Limit);
            }
            let content = doc.add_object(Stream::new(Dictionary::new(), bytes));
            let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>parent,"MediaBox"=>vec![0.into(),0.into(),Object::Real(self.page.width as f32),Object::Real(self.page.height as f32)],"Resources"=>dictionary!{"Font"=>fonts.clone()},"Contents"=>content});
            kids.push(Object::Reference(page));
        }
        doc.objects.insert(
            parent,
            dictionary! {"Type"=>"Pages","Count"=>kids.len() as i64,"Kids"=>kids}.into(),
        );
        let root = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>parent});
        doc.trailer.set("Root", root);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes)
            .map_err(|_| ContentTemplateError::Overflow)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(ContentTemplateError::Limit);
        }
        Ok(bytes)
    }
}
fn op(ops: &mut Vec<Operation>, name: &str, values: &[f64]) {
    ops.push(Operation::new(
        name,
        values.iter().map(|n| Object::Real(*n as f32)).collect(),
    ));
}
