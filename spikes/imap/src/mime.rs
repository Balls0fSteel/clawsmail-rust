//! A library-neutral MIME tree built from an IMAP BODYSTRUCTURE.
//!
//! This is the shape `cm-imap` would hand to `cm-store` and the UI: part numbers ready for
//! `BODY.PEEK[<section>]`, a lower-case MIME type, the transfer encoding, the size, and a
//! filename taken from the disposition or the `name` parameter. Each candidate library has its
//! own converter into this type (`cand_async_imap::to_mime_tree`,
//! `cand_imap_next::to_mime_tree`), so the comparison is about the libraries, not the tree.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MimePart {
    /// IMAP section number: `""` for the root of a multipart message, `"1"` for a single-part
    /// message's only part, `"1.2"` and so on below that.
    pub section: String,
    /// Lower-case `type/subtype`.
    pub mime_type: String,
    /// Lower-case parameter names with their values, in server order.
    pub params: Vec<(String, String)>,
    /// Lower-case Content-Transfer-Encoding (empty for multiparts).
    pub encoding: String,
    /// Encoded size in octets as reported by the server (0 for multiparts).
    pub size: u32,
    /// Lines, for text/* and message/rfc822 parts.
    pub lines: Option<u32>,
    pub content_id: Option<String>,
    /// Lower-case disposition type (`attachment`, `inline`).
    pub disposition: Option<String>,
    pub filename: Option<String>,
    pub children: Vec<MimePart>,
}

impl MimePart {
    pub fn new(section: String, mime_type: String) -> Self {
        Self {
            section,
            mime_type,
            params: Vec::new(),
            encoding: String::new(),
            size: 0,
            lines: None,
            content_id: None,
            disposition: None,
            filename: None,
            children: Vec::new(),
        }
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Depth-first list of every node.
    pub fn flatten(&self) -> Vec<&MimePart> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.flatten());
        }
        out
    }

    pub fn find(&self, section: &str) -> Option<&MimePart> {
        self.flatten().into_iter().find(|p| p.section == section)
    }

    /// Leaf parts that look like attachments (have a filename or `attachment` disposition).
    pub fn attachments(&self) -> Vec<&MimePart> {
        self.flatten()
            .into_iter()
            .filter(|p| p.children.is_empty() || p.mime_type == "message/rfc822")
            .filter(|p| p.filename.is_some() || p.disposition.as_deref() == Some("attachment"))
            .collect()
    }

    /// Fill `filename` from the disposition `filename` parameter or the content-type `name`.
    pub fn resolve_filename(&mut self, disposition_params: &[(String, String)]) {
        self.filename = disposition_params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("filename"))
            .map(|(_, v)| v.clone())
            .or_else(|| self.param("name").map(str::to_string));
    }
}

/// Section number of the `index`th (0-based) child of `parent`.
///
/// IMAP numbering: children of a multipart are `parent.N`; the root multipart's children are
/// `N`. The body of a message/rfc822 part shares the message part's number for its own
/// children, i.e. the children of the embedded multipart in part `2` are `2.1`, `2.2`.
pub fn child_section(parent: &str, index: usize) -> String {
    if parent.is_empty() { format!("{}", index + 1) } else { format!("{parent}.{}", index + 1) }
}

/// Section of the body embedded in a message/rfc822 part at `msg_section`.
///
/// The tree keeps the embedded body as the single child of the message/rfc822 node. A multipart
/// body shares the message part's number (its children are `2.1`, `2.2`); a single-part body
/// is `2.1`.
pub fn embedded_section(msg_section: &str, embedded_is_multipart: bool) -> String {
    if embedded_is_multipart { msg_section.to_string() } else { format!("{msg_section}.1") }
}

/// Section of the root node: `""` for a multipart message, `"1"` for a single-part one.
pub fn root_section(is_multipart: bool) -> String {
    if is_multipart { String::new() } else { "1".to_string() }
}
