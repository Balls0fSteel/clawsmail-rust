//! Assertions shared by both candidates' tests, so both are held to the same expectations.
#![allow(dead_code)]

use imap_spike::mime::MimePart;

pub type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub const USER: &str = "user@gmail.com";
pub const TOKEN: &str = "ya29.a0-test-token";

pub fn b64_decode(s: &str) -> String {
    use base64::Engine as _;
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
}

/// Run a test body with a hard timeout so a library that hangs fails instead of blocking.
pub async fn timed<F: std::future::Future<Output = TestResult>>(f: F) -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(15), f)
        .await
        .map_err(|_| "test timed out (client hung?)")?
}

/// UID 101: multipart/mixed { alternative { plain 1.1, html 1.2 }, pdf 2, png 3 }.
pub fn assert_tree_101(t: &MimePart) {
    assert_eq!(t.section, "");
    assert_eq!(t.mime_type, "multipart/mixed");
    assert_eq!(t.param("boundary"), Some("mix-b"));
    assert_eq!(t.children.len(), 3);

    let alt = &t.children[0];
    assert_eq!((alt.section.as_str(), alt.mime_type.as_str()), ("1", "multipart/alternative"));
    let plain = t.find("1.1").expect("1.1");
    assert_eq!(plain.mime_type, "text/plain");
    assert_eq!(plain.encoding, "quoted-printable");
    assert_eq!((plain.size, plain.lines), (1234, Some(30)));
    assert_eq!(plain.param("charset"), Some("utf-8"));
    let html = t.find("1.2").expect("1.2");
    assert_eq!((html.mime_type.as_str(), html.encoding.as_str(), html.size), ("text/html", "base64", 5678));

    let pdf = t.find("2").expect("2");
    assert_eq!(pdf.mime_type, "application/pdf");
    assert_eq!(pdf.encoding, "base64");
    assert_eq!(pdf.size, 102_400);
    assert_eq!(pdf.disposition.as_deref(), Some("attachment"));
    assert_eq!(pdf.filename.as_deref(), Some("report.pdf"));

    let png = t.find("3").expect("3");
    assert_eq!(png.mime_type, "image/png");
    assert_eq!(png.content_id.as_deref(), Some("<img1@example.com>"));
    assert_eq!(png.disposition.as_deref(), Some("inline"));
    assert_eq!(png.filename.as_deref(), Some("logo.png"));

    let att: Vec<_> = t.attachments().iter().map(|p| p.section.clone()).collect();
    assert_eq!(att, ["2", "3"]);
}

/// UID 102: multipart/mixed { plain 1, message/rfc822 2 { alternative { plain 2.1, html 2.2 } } }.
pub fn assert_tree_102(t: &MimePart) {
    assert_eq!(t.mime_type, "multipart/mixed");
    assert_eq!(t.children.len(), 2);
    let msg = &t.children[1];
    assert_eq!((msg.section.as_str(), msg.mime_type.as_str()), ("2", "message/rfc822"));
    assert_eq!(msg.size, 3000);
    assert_eq!(msg.lines, Some(60));
    assert_eq!(msg.filename.as_deref(), Some("forwarded.eml"));
    assert_eq!(msg.children.len(), 1, "embedded body");
    assert_eq!(msg.children[0].mime_type, "multipart/alternative");
    let inner_plain = &msg.children[0].children[0];
    let inner_html = &msg.children[0].children[1];
    assert_eq!((inner_plain.section.as_str(), inner_plain.mime_type.as_str()), ("2.1", "text/plain"));
    assert_eq!((inner_html.section.as_str(), inner_html.mime_type.as_str()), ("2.2", "text/html"));
    assert_eq!(inner_html.size, 200);
}

/// UID 103: a single text/plain part, section "1".
pub fn assert_tree_103(t: &MimePart) {
    assert_eq!(t.section, "1");
    assert_eq!(t.mime_type, "text/plain");
    assert_eq!(t.encoding, "8bit");
    assert_eq!(t.param("charset"), Some("iso-8859-2"));
    assert_eq!(t.param("format"), Some("flowed"));
    assert!(t.children.is_empty());
}

/// Special-use role of a LIST entry, from its attribute strings (`\Sent`, `\HasNoChildren`, ...).
pub fn special_use<'a>(attrs: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    for a in attrs {
        let role = match a.to_ascii_lowercase().as_str() {
            "\\sent" => "sent",
            "\\trash" => "trash",
            "\\drafts" => "drafts",
            "\\junk" => "junk",
            "\\all" => "all",
            "\\archive" => "archive",
            "\\flagged" => "flagged",
            "\\important" => "important",
            _ => continue,
        };
        return Some(role);
    }
    None
}

pub const APPEND_MSG: &[u8] =
    b"From: me@example.net\r\nTo: you@example.com\r\nSubject: Sent copy\r\n\r\nHello there.\r\n";
