//! The fake message shown in the mail view, its inline (`cid:`) parts, and the HTML wrapper
//! that adds the Content-Security-Policy.
//!
//! In the real app the HTML comes from `cm-mime`, is cleaned by `ammonia` in `cm-html`, and the
//! `cid:` rewrite happens on the sanitised DOM. Here a plain string replacement is enough.

/// Origin that `cid:` references are rewritten to. `.invalid` is reserved (RFC 2606) and can
/// never resolve, so even if the request handler failed nothing would leave the machine.
pub const CID_ORIGIN: &str = "https://cid.invalid/";

/// One MIME part of the message that can be referenced by `Content-ID`.
pub struct Part {
    pub content_id: &'static str,
    pub mime: &'static str,
    pub data: &'static [u8],
}

pub struct Message {
    /// The `text/html` body exactly as it came out of the MIME parser.
    pub html: &'static str,
    /// The `multipart/related` siblings of the HTML body.
    pub parts: Vec<Part>,
}

impl Message {
    pub fn part(&self, content_id: &str) -> Option<&Part> {
        self.parts.iter().find(|p| p.content_id == content_id)
    }
}

pub fn sample() -> Message {
    Message {
        html: SAMPLE_HTML,
        parts: vec![Part {
            content_id: "logo@clawsmail",
            mime: "image/png",
            data: include_bytes!("../assets/logo.png"),
        }],
    }
}

/// Rewrites `cid:` URLs in `src` attributes (and CSS `url(cid:...)`) to [`CID_ORIGIN`].
pub fn rewrite_cid(html: &str) -> String {
    html.replace("\"cid:", &format!("\"{CID_ORIGIN}"))
        .replace("'cid:", &format!("'{CID_ORIGIN}"))
        .replace("url(cid:", &format!("url({CID_ORIGIN}"))
}

/// The strict policy for message content. `allow_scripts` exists only for the positive control
/// run (`--allow-scripts`), which proves the probe would notice a script that did run.
pub fn csp(allow_scripts: bool) -> String {
    let script = if allow_scripts { "script-src 'unsafe-inline'; " } else { "" };
    format!(
        "default-src 'none'; {script}img-src {cid}; style-src 'unsafe-inline'; \
         font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; \
         form-action 'none'; base-uri 'none'",
        cid = CID_ORIGIN.trim_end_matches('/'),
    )
}

/// Builds the document handed to `NavigateToString`: the CSP meta tag goes first in `<head>`,
/// before anything from the message, so it applies to every element of the message.
pub fn document(msg: &Message, csp: Option<&str>) -> String {
    let body = rewrite_cid(msg.html);
    let meta = match csp {
        Some(policy) => format!(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\">\n"
        ),
        None => String::new(),
    };
    // A real message may have its own <head>; insert right after "<head>" when present.
    match body.find("<head>") {
        Some(i) => {
            let at = i + "<head>".len();
            format!("{}\n{meta}{}", &body[..at], &body[at..])
        }
        None => format!("<!doctype html><html><head>{meta}</head><body>{body}</body></html>"),
    }
}

/// A hostile-ish newsletter: a script, a tracking pixel, a remote CSS background, a meta refresh
/// away from the page, an ordinary link and a `target=_blank` link, plus one inline `cid:` image.
const SAMPLE_HTML: &str = r##"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="2;url=https://example.com/meta-refresh-away">
<title>Claws Mail Rust newsletter</title>
<style>
  body { font: 14px "Segoe UI", system-ui, sans-serif; margin: 14px 18px; color: #1d2330; background: #ffffff; }
  h2 { margin: 0 0 8px; font-size: 18px; }
  .probe { padding: 6px 10px; border-radius: 4px; font-weight: 600; }
  .ok { background: #dff3e4; border: 1px solid #3a9a5b; }
  .bad { background: #ff4d4d; border: 3px solid #900; color: #fff; font-size: 20px; }
  .box { border: 1px dashed #99a; padding: 4px 8px; margin: 6px 0; }
  img { vertical-align: middle; }
</style>
</head>
<body>
<h2>WebView2 safety spike</h2>
<p id="script-probe" class="probe ok">Scripts are OFF: an inline &lt;script&gt; in this mail would have replaced this line.</p>
<div class="box">Inline image from the message itself (<code>cid:logo@clawsmail</code>):
  <img id="cid-img" src="cid:logo@clawsmail" alt="[cid image missing]"></div>
<div class="box">Remote tracking pixel (<code>https://example.com/track.png</code>), must not load:
  <img id="tracker" src="https://example.com/track.png" width="48" height="48" alt="[blocked]"></div>
<div class="box" style="background-image: url(https://example.com/bg.png)">Remote CSS background (<code>https://example.com/bg.png</code>), must not load.</div>
<p><a id="away" href="https://example.com/phish">An ordinary link</a> &middot;
   <a id="blank" href="https://example.com/popup" target="_blank">A target=_blank link</a></p>
<script>
  document.title = "SCRIPT RAN";
  var p = document.getElementById("script-probe");
  p.textContent = "SCRIPT RAN: scripts are ON";
  p.className = "probe bad";
  document.body.style.background = "#ffb3b3";
  new Image().src = "https://example.com/script-beacon.gif";
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_cid_and_inserts_csp_first() {
        let doc = document(&sample(), Some(&csp(false)));
        assert!(doc.contains("src=\"https://cid.invalid/logo@clawsmail\""));
        assert!(!doc.contains("\"cid:"));
        let head = doc.find("<head>").unwrap();
        let meta = doc.find("Content-Security-Policy").unwrap();
        let refresh = doc.find("http-equiv=\"refresh\"").unwrap();
        assert!(head < meta && meta < refresh);
        assert!(!csp(false).contains("script-src"));
    }
}
