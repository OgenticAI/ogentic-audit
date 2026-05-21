//! Minimal hand-rolled PDF writer for the `export` subcommand.
//!
//! Why hand-rolled instead of `printpdf` / `genpdf`:
//!
//! 1. **Bit-reproducibility**. PDF libraries embed creation timestamps
//!    and producer strings that are awkward to override; some embed
//!    transient state via `/ID` arrays. A hand-rolled writer gives us
//!    explicit control over every byte in the file.
//! 2. **Small surface**. The court-ready PDF is text-only on
//!    Letter-size pages with built-in PDF fonts (Helvetica /
//!    Helvetica-Bold / Courier). No images, no embeds.
//! 3. **No dependencies**. Avoids pulling 30+ transitive crates for a
//!    feature whose runtime is the once-per-export path.
//!
//! The output is a PDF 1.4 document (universally supported). Built-in
//! fonts only — Helvetica, Helvetica-Bold, Courier. Letter-size pages
//! (612 × 792 pt). UTF-8 input is restricted to WinAnsiEncoding at
//! emit time (printable ASCII + a handful of common Latin-1
//! characters); anything outside that range is replaced with `?` to
//! avoid font-encoding ambiguity.

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

/// One page worth of content stream operators.
struct Page {
    /// Already-encoded content-stream bytes (BT/ET wraps already in).
    content: Vec<u8>,
}

/// PDF builder. Manages a sequence of pages and the cross-reference
/// table; emit a bit-reproducible PDF byte string via `finish`.
pub struct PdfBuilder {
    pages: Vec<Page>,
    current_y: f32,
    /// Producer string baked into the document. Required for
    /// reproducibility (we pin a known value).
    producer: String,
    /// Optional /Title field.
    title: String,
}

const PAGE_WIDTH: f32 = 612.0; // 8.5" * 72
const PAGE_HEIGHT: f32 = 792.0; // 11" * 72
const MARGIN: f32 = 54.0; // 0.75"
const LINE_HEIGHT: f32 = 14.0;
const TOP_Y: f32 = PAGE_HEIGHT - MARGIN;
const BOTTOM_Y: f32 = MARGIN;

impl PdfBuilder {
    /// Construct a new PDF document with the given title + producer.
    pub fn new(title: impl Into<String>, producer: impl Into<String>) -> Self {
        Self {
            pages: Vec::new(),
            current_y: TOP_Y,
            producer: producer.into(),
            title: title.into(),
        }
    }

    /// Start a new page.
    pub fn new_page(&mut self) {
        self.pages.push(Page {
            content: Vec::with_capacity(2048),
        });
        self.current_y = TOP_Y;
    }

    /// Write a header line (Helvetica-Bold, 16pt).
    pub fn h1(&mut self, text: &str) {
        self.text(Font::Bold, 16.0, text);
        self.current_y -= 4.0; // extra padding under headers
    }

    /// Write a subheading (Helvetica-Bold, 12pt).
    pub fn h2(&mut self, text: &str) {
        self.text(Font::Bold, 12.0, text);
    }

    /// Write a body line (Helvetica, 10pt).
    pub fn body(&mut self, text: &str) {
        self.text(Font::Regular, 10.0, text);
    }

    /// Write a monospace line (Courier, 9pt) — used for hex.
    pub fn mono(&mut self, text: &str) {
        self.text(Font::Mono, 9.0, text);
    }

    /// Blank line spacing.
    pub fn skip(&mut self) {
        self.current_y -= LINE_HEIGHT;
    }

    fn text(&mut self, font: Font, size: f32, text: &str) {
        // Auto-flow: if the next line would overflow, start a new page.
        if self.pages.is_empty() {
            self.new_page();
        }
        if self.current_y < BOTTOM_Y + LINE_HEIGHT {
            self.new_page();
        }
        let escaped = escape_pdf_string(text);
        let line_height = size + 2.0;
        let page = self.pages.last_mut().expect("page exists");
        let mut buf = String::new();
        let _ = writeln!(buf, "BT");
        let _ = writeln!(buf, "{} {} Tf", font.resource_name(), fmt_f(size));
        let _ = writeln!(buf, "{} {} Td", fmt_f(MARGIN), fmt_f(self.current_y));
        let _ = writeln!(buf, "({}) Tj", escaped);
        let _ = writeln!(buf, "ET");
        page.content.extend_from_slice(buf.as_bytes());
        self.current_y -= line_height;
    }

    /// Finalize the document into a byte vector.
    pub fn finish(self) -> Vec<u8> {
        // Object IDs:
        // 1: Catalog
        // 2: Pages
        // 3..3+N-1: Page N
        // 3+N: Font /F1 (Helvetica)
        // 4+N: Font /F2 (Helvetica-Bold)
        // 5+N: Font /F3 (Courier)
        // 6+N: Resources
        // 7+N..: per-page content streams
        // last: /Info dict
        let num_pages = self.pages.len().max(1);
        // Ensure at least one page exists.
        let pages_to_emit: Vec<Page> = if self.pages.is_empty() {
            vec![Page {
                content: Vec::new(),
            }]
        } else {
            self.pages
        };

        let id_catalog = 1usize;
        let id_pages = 2usize;
        let id_page_first = 3usize;
        let id_page_last = id_page_first + num_pages - 1;
        let id_font_f1 = id_page_last + 1;
        let id_font_f2 = id_font_f1 + 1;
        let id_font_f3 = id_font_f2 + 1;
        let id_resources = id_font_f3 + 1;
        let id_content_first = id_resources + 1;
        let id_info = id_content_first + num_pages;
        let total_ids = id_info; // inclusive

        // Render every object into a (id, bytes) list.
        let mut objects: Vec<(usize, Vec<u8>)> = Vec::with_capacity(total_ids);

        // Catalog
        objects.push((
            id_catalog,
            format!("<< /Type /Catalog /Pages {} 0 R >>", id_pages).into_bytes(),
        ));

        // Pages
        let kids: String = (0..num_pages)
            .map(|i| format!("{} 0 R", id_page_first + i))
            .collect::<Vec<_>>()
            .join(" ");
        objects.push((
            id_pages,
            format!("<< /Type /Pages /Kids [{kids}] /Count {} >>", num_pages).into_bytes(),
        ));

        // Each Page references the shared Resources + its content stream.
        for i in 0..num_pages {
            let content_id = id_content_first + i;
            objects.push((
                id_page_first + i,
                format!(
                    "<< /Type /Page /Parent {} 0 R /Resources {} 0 R \
                     /MediaBox [0 0 {} {}] /Contents {} 0 R >>",
                    id_pages,
                    id_resources,
                    fmt_f(PAGE_WIDTH),
                    fmt_f(PAGE_HEIGHT),
                    content_id,
                )
                .into_bytes(),
            ));
        }

        // Fonts.
        objects.push((
            id_font_f1,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
                .to_vec(),
        ));
        objects.push((
            id_font_f2,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
                .to_vec(),
        ));
        objects.push((
            id_font_f3,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
                .to_vec(),
        ));

        // Resources.
        objects.push((
            id_resources,
            format!(
                "<< /Font << /F1 {} 0 R /F2 {} 0 R /F3 {} 0 R >> >>",
                id_font_f1, id_font_f2, id_font_f3,
            )
            .into_bytes(),
        ));

        // Content streams (per-page).
        for (i, page) in pages_to_emit.iter().enumerate() {
            let stream_bytes = &page.content;
            let mut buf = Vec::new();
            buf.extend_from_slice(
                format!("<< /Length {} >>\nstream\n", stream_bytes.len()).as_bytes(),
            );
            buf.extend_from_slice(stream_bytes);
            buf.extend_from_slice(b"\nendstream");
            objects.push((id_content_first + i, buf));
        }

        // /Info dict — no timestamps, just title + producer (both
        // caller-fixed).
        objects.push((
            id_info,
            format!(
                "<< /Title ({}) /Producer ({}) >>",
                escape_pdf_string(&self.title),
                escape_pdf_string(&self.producer),
            )
            .into_bytes(),
        ));

        // Sort by id and emit.
        objects.sort_by_key(|(id, _)| *id);

        let mut out = Vec::<u8>::with_capacity(8192);
        // Header (binary marker per PDF 1.4 convention to make sure
        // viewers treat the file as binary).
        out.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");

        // Track byte offset for xref.
        let mut offsets = vec![0usize; total_ids + 1]; // 1-indexed
        for (id, body) in &objects {
            offsets[*id] = out.len();
            out.extend_from_slice(format!("{} 0 obj\n", id).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }

        let xref_offset = out.len();
        out.extend_from_slice(b"xref\n");
        out.extend_from_slice(format!("0 {}\n", total_ids + 1).as_bytes());
        // Free object 0
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().take(total_ids + 1).skip(1) {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(b"trailer\n");
        out.extend_from_slice(
            format!(
                "<< /Size {} /Root {} 0 R /Info {} 0 R >>\n",
                total_ids + 1,
                id_catalog,
                id_info,
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"startxref\n");
        out.extend_from_slice(format!("{}\n", xref_offset).as_bytes());
        out.extend_from_slice(b"%%EOF\n");

        out
    }
}

#[derive(Copy, Clone)]
enum Font {
    Regular,
    Bold,
    Mono,
}

impl Font {
    fn resource_name(self) -> &'static str {
        match self {
            Font::Regular => "/F1",
            Font::Bold => "/F2",
            Font::Mono => "/F3",
        }
    }
}

/// Escape a string for use inside a PDF `(string)` literal. PDF
/// strings use parentheses; `(`, `)`, and `\` must be backslash-
/// escaped. Anything outside WinAnsiEncoding's printable range
/// becomes `?` — court-ready content is text-only ASCII / Latin-1
/// per the spec we control.
fn escape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        let c = ch as u32;
        match ch {
            '(' | ')' | '\\' => {
                out.push('\\');
                out.push(ch);
            },
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if (0x20..=0x7e).contains(&c) || (0xa0..=0xff).contains(&c) => out.push(ch),
            _ => out.push('?'),
        }
    }
    out
}

/// Format a float with one decimal place. PDF accepts integers without
/// a trailing `.0`, so we drop the fractional when zero — improves
/// reproducibility across machines that print floats slightly
/// differently (e.g. fast-math).
fn fmt_f(n: f32) -> String {
    if (n.fract()).abs() < 1e-6 {
        format!("{}", n as i64)
    } else {
        format!("{n:.2}")
    }
}

/// Write the produced bytes to disk. Used by the export command.
pub fn write_pdf<W: Write>(mut w: W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(bytes)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pdf_is_valid_shape() {
        let pdf = PdfBuilder::new("Test", "ogentic-audit/test").finish();
        // Starts with PDF header.
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        // Ends with EOF marker.
        assert!(pdf.ends_with(b"%%EOF\n"));
        // Has at least one cross-reference entry.
        assert!(pdf.windows(5).any(|w| w == b"xref\n"));
    }

    #[test]
    fn pdf_is_bit_reproducible_for_same_inputs() {
        let mut a = PdfBuilder::new("Title", "ogentic-audit/0.1.0a0");
        a.h1("Heading");
        a.body("body line one");
        a.body("body line two");
        let pdf_a = a.finish();

        let mut b = PdfBuilder::new("Title", "ogentic-audit/0.1.0a0");
        b.h1("Heading");
        b.body("body line one");
        b.body("body line two");
        let pdf_b = b.finish();

        assert_eq!(pdf_a, pdf_b, "PDFs differ for identical inputs");
    }

    #[test]
    fn escapes_parens_and_backslashes() {
        assert_eq!(escape_pdf_string("foo (bar)"), "foo \\(bar\\)");
        assert_eq!(escape_pdf_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn escapes_non_winansi_chars() {
        // Emoji is outside WinAnsi; should be replaced.
        assert!(escape_pdf_string("🎉").contains('?'));
    }
}
